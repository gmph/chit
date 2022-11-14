import os
import re
import time
import datetime
import requests
import secrets
from urllib.parse import urlparse
from fastapi import FastAPI, Request, Depends, Security, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.security import APIKeyCookie
from colorhash import ColorHash
from pydantic import BaseModel
from deta import Deta

class Post(BaseModel):
  text: str
  time: int

password_cookie = APIKeyCookie(name="password", auto_error=False)

app = FastAPI(
    title="chit",
    description="Chit is a self-hosted, distributed micro-social network",
    version="0.0.1",
    contact={
        "name": "Graham Macphee",
        "url": "https://grahammacphee.com",
    },
)

async def is_authenticated(password: str = Security(password_cookie)):
  try:
    password_file_contents = await read_file('password.txt')
    if password and len(password) and password_file_contents and password_file_contents:
      correct_password_bytes = password_file_contents.encode("utf8")
      current_password_bytes = password.encode("utf8")
      is_correct_password = secrets.compare_digest(
          current_password_bytes, correct_password_bytes
      )
    else:
      is_correct_password = False
    return is_correct_password
  except Exception as e:
    print (e)
    return False

@app.get('/set-password/{password}', tags=["authentication"], response_class=RedirectResponse, responses={307: {"description": "Successfully saved password as cookie and redirected"}})
@app.get('/set-password/{password}/{old_password}', tags=["authentication"], response_class=RedirectResponse, responses={307: {"description": "Successfully saved password as cookie and redirected"}})
async def set_password(request: Request, password: str, old_password: str = '', authenticated: bool = Depends(is_authenticated)):
  prev_password = await read_file('password.txt')
  if old_password == prev_password:
    await write_file('password.txt', new_data=password)
    response = RedirectResponse('/')
    response.set_cookie('password', password, max_age=1000*60*60*24*30, samesite='strict', httponly=True)
    return response
  else:
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data=None, 
      status_code=403, 
      title='Cannot set password', 
      content='Check that the previous password is correct. It should be provided in the form: <code>/set-password/{password}/{old_password}</code>',
    )

@app.get('/login/{password}', tags=["authentication"], response_class=RedirectResponse, responses={307: {"description": "Successfully saved password as cookie and redirected"}})
async def log_in(password: str):
  response = RedirectResponse('/')
  response.set_cookie('password', password, max_age=1000*60*60*24*30, samesite='strict', httponly=True)
  return response

@app.get('/', tags=["feed"], responses={200: {"description": "Successfully got feed as authenticated user"}, 307: {"description": "Redirected to /posts as unauthorized user"}})
async def get_feed(request: Request, authenticated: bool = Depends(is_authenticated)):
  if not authenticated:
    return RedirectResponse('/posts')
  current_url = urlparse(request.url._url)
  normalized_current_url = current_url.scheme + '://' + current_url.netloc
  posts = []
  post_file = await read_file('posts.txt')
  posts = get_posts_list_from_raw_file(post_file, normalized_current_url)
  following_file = await read_file('following.txt')
  following = following_file.splitlines()
  for following_url in following:
    following_url_parsed = urlparse(following_url)
    normalized_following_url = (following_url_parsed.scheme if following_url_parsed.scheme else 'https') + '://' + following_url_parsed.netloc
    try:
      response = requests.get(normalized_following_url + '/posts', allow_redirects=False, timeout=5, headers={'Accept': 'text/plain'})
      if str(response.status_code)[0] != '2':
        raise Exception("Unable to get posts for a URL: " + str(normalized_following_url))
      posts_for_url = get_posts_list_from_raw_file(response.text, normalized_following_url)
      posts += posts_for_url
    except Exception as e:
      print(e)
  posts.sort(reverse=True, key=lambda p: p.get("time"))
  list_items_html = list(map(lambda p: get_post_item_html(p.get('url'), p.get('text'), p.get('time')), posts))
  content_html = (get_create_post_html(normalized_current_url) if authenticated else '')
  return html_or_raw_response(
    request, 
    authenticated=authenticated,
    data=posts, 
    status_code=200, 
    title='Feed', 
    content=content_html,
    list_items=list_items_html
  )

@app.get('/posts', tags=["posts"], response_model=list[Post], responses={200: {"description": "Successfully got posts"}})
async def get_posts(request: Request, authenticated: bool = Depends(is_authenticated)):
  try:
    current_url = urlparse(request.url._url)
    normalized_current_url = current_url.scheme + '://' + current_url.netloc
    post_file = await read_file('posts.txt')
    posts = get_posts_list_from_raw_file(post_file, normalized_current_url)
    posts.sort(reverse=True, key=lambda p: p.get("time"))
    list_items_html = list(map(lambda p: get_post_item_html(p.get('url'), p.get('text'), p.get('time')),posts))
    about = await get_variables()
    title = ('Posts by ' + str(about.get('name'))) if about and about.get('name') else 'Posts'
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data=post_file, 
      status_code=200, 
      title=title, 
      list_items=list_items_html
    )
  except Exception as e:
    print (e)
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data='', 
      status_code=200, 
      title='Posts', 
      content='No posts available',
    )

@app.post('/posts/create', tags=["posts"], response_class=RedirectResponse, responses={401: {"class": JSONResponse}, 303: {"description": "Successfully posted and redirected", "class": RedirectResponse}})
async def create_post(request: Request, text: str = Form(), authenticated: bool = Depends(is_authenticated)):
  if not authenticated:
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data=None, 
      status_code=401, 
      title='Not authorized', 
      content='You do not have permission to create a post',
    )
  t = round(time.time() * 1000)
  new_lines = [
    "[" + str(t) + "]\n" + text + "\n\n",
  ]
  await write_file('posts.txt', new_lines=new_lines)
  return RedirectResponse('/', status_code=303)

@app.get('/posts/{post_id}', tags=["posts"], response_model=Post, responses={200: {"description": "Successfully got post", "model": Post}})
async def get_post(post_id: str, request: Request, authenticated: bool = Depends(is_authenticated)):
  posts_file = await read_file('posts.txt')
  post_text = None
  match = False
  for line in posts_file:
    if match:
      post_text = line
      break
    elif line.startswith('[' + post_id + ']'):
      match = True
  post = {
    "time": int(post_id),
    "text": re.sub(r"\n$","",post_text)
  } if post_text else None
  return html_or_raw_response(
    request, 
    authenticated=authenticated,
    data=post, 
    status_code=200, 
    title=post.get('text'), 
    content=get_readable_datetime(post.get('time')),
  )

@app.get('/following', tags=["following"], response_model=list[str])
async def get_following(request: Request, authenticated: bool = Depends(is_authenticated)):
  try:
    following_file = await read_file('following.txt')
    following = following_file.splitlines()
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data=following_file, 
      status_code=200, 
      title='Following', 
      content=add_following_html() if authenticated else None,
      list_items=list(map(lambda f: get_url_avatar_html(f) + get_url_as_readable_link_html(f), following)),
    )
  except:
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data='', 
      status_code=200, 
      title='Following', 
      content=(add_following_html() if authenticated else '') + '<p>Not following any URLs</p>',
    )

@app.post('/following/add', tags=["following"], response_model=bool, responses={303: {"description": "Successfully added URL as follower and redirected", "model": bool}, 401: {"description": "Unauthorized", "model": bool}, 405: {"description": "Unable to follow URL", "model": bool} })
async def follow_another_url(request: Request, url: str = Form(), authenticated: bool = Depends(is_authenticated)):
  if not authenticated:
    return html_or_raw_response(
      request,
      authenticated=authenticated,
      data='',
      status_code=401, 
      title='Not authorized', 
      content='You do not have permission to follow on behalf of this URL',
    )
  try:
    url_to_follow = urlparse(re.sub(r"^(?!https?\:\/\/)", "https://", url))
    normalized_url_to_follow = (url_to_follow.scheme if url_to_follow.scheme else 'https') + '://' + url_to_follow.netloc
    await write_file('following.txt', new_lines=[url])
    current_url = urlparse(request.url._url)
    normalized_current_url = current_url.scheme + '://' + current_url.netloc
    response_add_follower = requests.post(normalized_url_to_follow + '/followers/add', data={"url": normalized_current_url}, allow_redirects=False)
    did_add_follower = str(response_add_follower.status_code)[0] != '2'
    return RedirectResponse('/following?confirmed=' + str(did_add_follower), status_code=303)
  except:
    return html_or_raw_response(
        request, 
        authenticated=authenticated,
        data='', 
        status_code=405, 
        title='Something went wrong', 
        content='This URL may not be valid, or it may not be a chit site', 
      )

@app.get('/followers', tags=["followers"], responses={200: {"description": "Successfully got followers", "class": JSONResponse}})
async def get_followers(request: Request, authenticated: bool = Depends(is_authenticated)):
  try:
    followers_file = await read_file("followers.txt")
    followers = followers_file.splitlines()
    if followers.count == 0 or len(followers[0]) < 4:
      raise Exception('No followers')
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data=followers_file, 
      status_code=200, 
      title='Followers', 
      list_items=list(map(lambda f: get_url_avatar_html(f) + get_url_as_readable_link_html(f), followers)),
    )
  except:
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data='', 
      status_code=200, 
      title='Followers', 
      content='Not followed by any URLs. See the <a href="/protocol">protocol</a> to learn how to add your site as a follower.',
    )

@app.post('/followers/add', tags=["followers"], responses={200: {"description": "Successfully added URL as a follower", "class": JSONResponse}, 405: {"description": "Not allowed to add URL as a follower", "class": JSONResponse}})
async def add_follower( request: Request, url: str = Form(), authenticated: bool = Depends(is_authenticated)):
  try:
    current_url = urlparse(request.url._url)
    requesting_url = urlparse(re.sub(r"^(?!https?\:\/\/)", "https://", url))
    normalized_requesting_url = (requesting_url.scheme if requesting_url.scheme else 'https') + '://' + requesting_url.netloc
    response = requests.get(normalized_requesting_url + '/following', allow_redirects=False, headers={'Accept': 'text/plain'})
    if str(response.status_code)[0] != '2':
      raise Exception("Unable to get following list for this URL")
    following: list[str] = []
    for line in response.text.splitlines():
      parsed_url = urlparse(line)
      following.append((parsed_url.scheme if parsed_url.scheme else 'https') + '://' + parsed_url.netloc)
    following_index: int = following.index(current_url.scheme + '://' + current_url.netloc)
    if following_index < 0:
      raise Exception("The current URL is not in the following list for the provided URL")
    await write_file('followers.txt', new_lines=[normalized_requesting_url])
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data='', 
      status_code=200, 
      title='Follower URL added successfully', 
    )
  except:
    return html_or_raw_response(
      request, 
      authenticated=authenticated,
      data='', 
      status_code=405, 
      title='Cannot add follower', 
      content='The <code>/following</code> file at the provided URL must include this URL'
    )

@app.get('/about', tags=["about"], response_class=HTMLResponse, status_code=200, responses={200: {"description": "Successfully got about"}})
async def get_about(request: Request, saved: bool = False, authenticated: bool = Depends(is_authenticated)):
  response = await get_page_for_file(
    file_name='about.txt',
    description='Set the about information for this site in the form <code>name = John Smith</code>. The supported fields are: <code>name</code>.',
    request=request,
    authenticated=authenticated,
    is_editable=True,
    is_public=True,
    is_local=False,
    is_key_value_file=True,
    did_save=saved,
  )
  return response

@app.post('/about', tags=["about"], response_class=RedirectResponse, status_code=303, responses={303: {"description": "Successfully updated about"}})
async def update_about(request: Request, data: str = Form(), authenticated: bool = Depends(is_authenticated)):
  response = await get_update_handler_for_file(
    file_name="about.txt",
    data=data,
    request=request,
    authenticated=authenticated,
  )
  return response

@app.get('/protocol', tags=["protocol"], response_class=HTMLResponse, status_code=200, responses={200: {"description": "Successfully got protocol"}})
async def get_about(request: Request, saved: bool = False, authenticated: bool = Depends(is_authenticated)):
  response = await get_page_for_file(
    file_name='protocol.txt',
    description='Edit information about this site',
    request=request,
    authenticated=authenticated,
    is_editable=False,
    is_public=True,
    is_local=True,
    is_key_value_file=False,
    did_save=saved,
  )
  return response

@app.get('/style.css', tags=["style"], response_class=PlainTextResponse, status_code=200, responses={200: {"description": "Successfully got styles"}})
async def get_style():
  style_file = await read_file('style.css', force_local=True)
  style_response = PlainTextResponse(style_file, status_code=200)
  return style_response



# helpers

def get_posts_list_from_raw_file(raw_file: str, url: str = ''):
  posts_in_parts = re.findall(r"\[([0-9]+?)\]\n((?:.|\n)+?)(?=(?:\n\n*\[[0-9]+?\]|\n\n\Z))", raw_file, flags=re.MULTILINE)
  posts_list = []
  for post in posts_in_parts:
    post_object = {
      "url": url,
      "time": int(post[0]),
      "text": post[1],
    }
    posts_list.append(post_object)
  return posts_list

def get_post_item_html(url: str, text: str, time: int):
  return get_url_avatar_html(url) + "<div><div>" + get_url_as_readable_link_html(url) + " on " + get_readable_datetime(time) + "</div><pre>" + get_text_with_linked_urls_html(get_text_with_basic_styling_html(text)) + "</pre></div>"

def get_url_avatar_html(url: str):
  parsed_url = urlparse(url)
  url_normalized = (parsed_url.scheme if parsed_url.scheme else 'https') + '://' + parsed_url.netloc
  color = ColorHash(url_normalized).hex
  readable_url = re.sub(r"^www\.", "", parsed_url.netloc)
  return '<span class="avatar" style="--data-initials: \'{initials}\'; --data-color: {color};"></span>'.format(initials=readable_url[0] if len(url) > 0 else '', color=color)

def get_url_as_readable_link_html(url: str):
  parsed_url = urlparse(url)
  full_valid_url = (parsed_url.scheme if parsed_url.scheme else 'https') + '://' + parsed_url.netloc + parsed_url.path
  readable_url = re.sub(r"^www\.", "", parsed_url.netloc)
  return '<a href="{full_valid_url}" target="_blank" noopener>{readable_url}</a>'.format(full_valid_url=full_valid_url, readable_url=readable_url)

def html_or_raw_response(request: Request, authenticated: bool, data: any, status_code: int = 200, title: str = None, content: str = None, list_items: list[str] = None):
  if is_server_request(request):
    response = PlainTextResponse(data, status_code=status_code)
    return response
  else:
    response = get_html_response(title=title, status_code=status_code, content=content, list_items=list_items, authenticated=authenticated)
    return response

def is_server_request(request: Request):
  return 'text/html' not in request.headers.get('Accept')

def add_following_html():
  form_html = """
    <p>Follow other sites that use the chit protocol.</p>
    <form action="/following/add" method="POST" autocomplete="off">
      <label for="url">URL:</label>
      <input type="url" id="url" name="url" value="" placeholder="https://example.com" required>
      <span>&nbsp;</span>
      <input type="submit" value="Add" onClick="this.form.submit(); this.disabled=true; this.value='Adding...';">
    </form>
    <hr/>
  """
  return form_html

def get_create_post_html(current_url: str):
  form_html = """
    <div>
      {avatar}
      <form id="create_post" action="/posts/create" method="POST" autocomplete="off">
        <label for="post">Create a post</label>
        <textarea id="text" name="text" form="create_post" value="" placeholder="Write something..." required style="width: 100%; resize: none" rows="3"></textarea>
        <input type="submit" value="Post" onClick="this.form.submit(); this.disabled=true; this.value='Posting...'; this.focus();">
      </form>
    </div>
    <hr/>
  """.format(avatar=get_url_avatar_html(current_url))
  return form_html

def get_html_response(title: str, status_code: int = 200, content: str = None, list_items: list[str] = None, authenticated: bool = False):
  head_html = '<head><title>' + title + '</title><link rel="stylesheet" type="text/css" href="/style.css" /><meta name="viewport" content="width=device-width, initial-scale=1.0" /></head>'
  page_title_html = "<h1>" + title + "</h1>"
  content_html = "<p>" + content + "</p>" if content else ""
  list_html = '<ul>' + ''.join(list(map(lambda item: "<li>" + item + "</li>", list_items))) + '</ul>' if list_items else ""
  link_to_feed_html = '<a href="/">Feed</a>' if authenticated else ''
  link_to_posts_html = '<a href="/posts">Posts</a>'
  link_to_following_html = '<a href="/following">Following</a>'
  link_to_followers_html = '<a href="/followers">Followers</a>'
  link_to_about_html = '<a href="/about">About</a>'
  link_to_protocol_html = '<a href="/protocol">Protocol</a>'
  links_html = '<nav>' + link_to_feed_html + ' ' + link_to_posts_html + ' ' + link_to_following_html + ' ' + link_to_followers_html + ' ' + link_to_about_html + ' ' + link_to_protocol_html + '</nav>'
  html = "<html>" + head_html + "<body>" + links_html +  "<hr/>" + page_title_html + content_html + list_html + "</body></html>"
  response = HTMLResponse(content=html, status_code=status_code)
  return response

def get_readable_datetime(time):
  return datetime.datetime.fromtimestamp(int(time)/1000.0).strftime('%a %d %b %Y, %H:%M')

async def read_file(file_name: str, force_local: bool = False):
  if (os.getenv('DETA_RUNTIME')) and force_local != True:
    deta  = Deta(os.getenv('DETA_PROJECT_KEY'))
    deta_drive = deta.Drive('chit')
    res = deta_drive.get(file_name)
    file_contents = res.read() if res else b''
    if res and res.close:
      res.close()
    return file_contents.decode('utf8')
  else:
    try:
      with open(file_name,"rt") as readable_file:
        file_contents = readable_file.read()
        readable_file.close()
        return file_contents
    except Exception as e:
      print(e)
      return ''

async def write_file(file_name: str, new_data: str = None, new_lines: list[str] = None):
  if new_lines:
    prev_content = await read_file(file_name)
    new_data = '\n'.join(prev_content.splitlines() + new_lines)
  if (os.getenv('DETA_RUNTIME')):
    deta  = Deta(os.getenv('DETA_PROJECT_KEY'))
    deta_drive = deta.Drive('chit')
    file_name = deta_drive.put(file_name, data=new_data.encode('utf8'), content_type='text/plain')
    return file_name
  else:
    with open(file_name,"w+t") as writable_file:
      writable_file.write(new_data)
      writable_file.close()
      return file_name

async def get_update_handler_for_file(file_name: str, data: str, request: Request, authenticated: bool):
  label = file_name.split('.')[0]
  if not authenticated:
    return html_or_raw_response(
      request=request, 
      authenticated=authenticated,
      data='',
      status_code=401,
      title='Unauthorized',
      content='You must be authorized to edit ' + label
    )
  if file_name and data:
    file_name = await write_file(file_name, data)
    return RedirectResponse('/' + label + '?saved=true', status_code=303)
  else:
    return html_or_raw_response(
      request=request, 
      authenticated=authenticated,
      data='',
      status_code=401,
      title="Couldn't edit " + label,
      content='The data saved may have been invalid'
    )

async def get_page_for_file(file_name: str, description: str, request: Request, authenticated: bool, is_local: bool = False, is_editable: bool = False, is_public: bool = False, did_save: bool = False, is_key_value_file: bool = False):
  label = file_name.split('.')[0]
  if not authenticated and not is_public:
    return html_or_raw_response(
      request=request, 
      authenticated=authenticated,
      data='',
      status_code=401,
      title='Unauthorized',
      content='You must be authorized to access ' + label
    )
  file = await read_file(file_name, force_local=is_local)
  if authenticated and is_editable:
    title = 'Edit ' + label
    save_notice = '&nbsp;&nbsp;<span>Saved successfully</span>' if did_save else ''
    page_html = """
        <p>{description}</p>
        <form id="form_{label}" action="{action}" method="POST" autocomplete="off">
          <label for="post">Edit {label}</label>
          <textarea id="data" name="data" form="form_{label}" required style="width: 100%; resize: none" rows="12">{file}</textarea>
          <input type="submit" value="Save" onClick="this.form.submit(); this.disabled=true; this.value='Saving...';"> {save_notice}
        </form>
      """.format(label=label, description=description, action=label, file=file, save_notice=save_notice)
    page_list_html = None
  else:
    title = label.capitalize()
    if is_key_value_file:
      variables = await get_variables(file)
      page_html = ''
      page_list_html = filter(lambda v: v != None, list(map(lambda v: None if v[0].startswith('_') else ('<strong>' + v[0].capitalize() + '</strong>: ' + get_text_with_linked_urls_html(v[1])), variables.items())))
    else:
      page_html = """
          <pre style="width: 100%;">{file}</pre>
        """.format(label=label, description=description, file=get_text_with_linked_urls_html(get_text_with_basic_styling_html(file)))
      page_list_html = None
  return html_or_raw_response(
    request=request, 
    authenticated=authenticated,
    data='',
    status_code=200,
    title=title,
    content=page_html,
    list_items=page_list_html
  )

async def get_variables(raw_file: str = None):
  variables = {}
  raw_variable_file = await read_file('about.txt') if not raw_file else raw_file
  variables.update({'_raw': raw_variable_file})
  lines = raw_variable_file.splitlines()
  for line in lines:
    line_parts = line.split('=')
    if len(line_parts) == 2:
      variables.update({line_parts[0].strip():line_parts[1].strip()})
  return variables

def get_text_with_linked_urls_html(text: str):
  linked_text_html = re.sub(
    r"(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)(?:[-a-zA-Z0-9()@:%_\+~#?&//=]+))",
    r'<a href="\1" target="_blank" noopener>\1</a>',
    text,
  )
  return linked_text_html

def get_text_with_basic_styling_html(text: str):
  bolded = re.sub(
    r"\*(.+?)\*",
    r'<strong>\1</strong>',
    text,
  )
  italicized = re.sub(
    r"_(.+?)_",
    r'<em>\1</em>',
    bolded,
  )
  struckthrough = re.sub(
    r"~(.+?)~",
    r'<strike>\1</strike>',
    italicized,
  )
  highlighted = re.sub(
    r"=(.+?)=",
    r'<mark>\1</mark>',
    struckthrough,
  )
  coded = re.sub(
    r"`(.+?)`",
    r'<code>\1</code>',
    highlighted,
  )
  line_reduced = re.sub(
    r"\n\n\n+",
    r"\n\n\n",
    coded,
  )
  return line_reduced
    
