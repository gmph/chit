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
from fastapi.staticfiles import StaticFiles
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
    return json_or_html_response(
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
  posts = []
  post_file = await read_file('posts.txt')
  # todo: extract post parsing
  posts_in_parts = re.findall(r"\[([0-9]*?)\]\n(.*?)\n", post_file, flags=re.MULTILINE)
  posts = []
  for post in posts_in_parts:
    posts.append({
      "url": request.url._url,
      "time": int(post[0]),
      "text": post[1]
    })
  following_file = await read_file('following.txt')
  following = following_file.splitlines()
  for following_url in following:
    following_url_parsed = urlparse(following_url)
    normalized_following_url = (following_url_parsed.scheme if following_url_parsed.scheme else 'https') + '://' + following_url_parsed.netloc
    try:
      response = requests.get(normalized_following_url + '/posts', allow_redirects=False, timeout=5)
      if str(response.status_code)[0] != '2':
        raise Exception("Unable to get posts for a URL: " + str(normalized_following_url))
      post_file = response.text
      # todo: extract post parsing
      posts_in_parts = re.findall(r"\[([0-9]*?)\]\n(.*?)\n", post_file, flags=re.MULTILINE)
      posts_for_url = []
      for post in posts_in_parts:
        posts_for_url.append({
          "url": normalized_following_url,
          "time": int(post[0]),
          "text": post[1],
        })
      posts += posts_for_url
    except Exception as e:
      print(e)
  posts.sort(reverse=True, key=lambda p: p.get("time"))
  list_items_html = list(map(lambda p: 
    "<div>" + p.get("text") + "</div><div>" + get_url_as_readable_link_html(p.get("url")) + " at " + get_readable_datetime(p.get("time")) + "<br/><br/></div>",
    posts
  ))
  content_html = (get_create_post_html() if authenticated else '')
  return json_or_html_response(
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
    post_file = await read_file('posts.txt')
    # todo: extract post parsing
    posts_in_parts = re.findall(r"\[([0-9]*?)\]\n(.*?)\n", post_file, flags=re.MULTILINE)
    posts = []
    for post in posts_in_parts:
      posts.append({
        "time": int(post[0]),
        "text": post[1]
      })
    posts.sort(reverse=True, key=lambda p: p.get("time"))
    list_items_html = list(map(lambda p: 
      "<div>" + p.get("text") + "</div><div>" + get_readable_datetime(p.get("time")) + "<br/><br/></div>",
      posts
    ))
    content_html = (get_create_post_html() if authenticated else '')
    return json_or_html_response(
      request, 
      authenticated=authenticated,
      data=posts, 
      status_code=200, 
      title='Posts', 
      content=content_html,
      list_items=list_items_html
    )
  except Exception as e:
    print (e)
    return json_or_html_response(
      request, 
      authenticated=authenticated,
      data=[], 
      status_code=200, 
      title='Posts', 
      content='No posts available',
    )

@app.post('/posts/create', tags=["posts"], response_class=RedirectResponse, responses={401: {"class": JSONResponse}, 303: {"description": "Successfully posted and redirected", "class": RedirectResponse}})
async def create_post(request: Request, text: str = Form(), authenticated: bool = Depends(is_authenticated)):
  if not authenticated:
    return json_or_html_response(
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
  return json_or_html_response(
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
    return json_or_html_response(
      request, 
      authenticated=authenticated,
      data=following, 
      status_code=200, 
      title='Following', 
      content=add_following_html() if authenticated else None,
      list_items=list(map(lambda f: get_url_as_readable_link_html(f), following)),
    )
  except:
    return json_or_html_response(
      request, 
      authenticated=authenticated,
      data=[], 
      status_code=200, 
      title='Following', 
      content=(add_following_html() if authenticated else '') + '<p>Not following any URLs</p>',
    )

@app.post('/following/add', tags=["following"], response_model=bool, responses={303: {"description": "Successfully added URL as follower and redirected", "model": bool}, 401: {"description": "Unauthorized", "model": bool}, 405: {"description": "Unable to follow URL", "model": bool} })
async def follow_another_url(request: Request, url: str = Form(), authenticated: bool = Depends(is_authenticated)):
  if not authenticated:
    return json_or_html_response(
      request,
      authenticated=authenticated,
      data=None,
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
    return json_or_html_response(
        request, 
        authenticated=authenticated,
        data=False, 
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
    return json_or_html_response(
      request, 
      authenticated=authenticated,
      data=followers, 
      status_code=200, 
      title='Followers', 
      list_items=list(map(lambda f: get_url_as_readable_link_html(f), followers)),
    )
  except:
    return json_or_html_response(
      request, 
      authenticated=authenticated,
      data=[], 
      status_code=200, 
      title='Followers', 
      content='Not followed by any URLs. Other sites can record that they follow this one by posting their URL to <code>/followers/add</code>.',
    )

@app.post('/followers/add', tags=["followers"], responses={200: {"description": "Successfully added URL as a follower", "class": JSONResponse}, 405: {"description": "Not allowed to add URL as a follower", "class": JSONResponse}})
async def add_follower( request: Request, url: str = Form(), authenticated: bool = Depends(is_authenticated)):
  try:
    current_url = urlparse(request.url._url)
    requesting_url = urlparse(re.sub(r"^(?!https?\:\/\/)", "https://", url))
    normalized_requesting_url = (requesting_url.scheme if requesting_url.scheme else 'https') + '://' + requesting_url.netloc
    response = requests.get(normalized_requesting_url + '/following', allow_redirects=False)
    if str(response.status_code)[0] != '2':
      raise Exception("Unable to get following list for this URL")
    following: list[str] =[]
    for line in response.text.splitlines():
      parsed_url = urlparse(line)
      following.append((parsed_url.scheme if parsed_url.scheme else 'https') + '://' + parsed_url.netloc)
    following_index: int = following.index(current_url.scheme + '://' + current_url.netloc)
    if following_index < 0:
      raise Exception("The current URL is not in the following list for the provided URL")
    await write_file('followers.txt', new_lines=[normalized_requesting_url, '\n'])
    return json_or_html_response(
      request, 
      authenticated=authenticated,
      data=True, 
      status_code=200, 
      title='Follower URL added successfully', 
    )
  except:
    return json_or_html_response(
      request, 
      authenticated=authenticated,
      data=True, 
      status_code=405, 
      title='Cannot add follower', 
      content='The <code>/following</code> file at the provided URL must include this URL'
    )

@app.get('/style.css', tags=["style"])
async def get_style():
  style_file = await read_file('style.css')
  style_response = PlainTextResponse(style_file, status_code=200)
  return style_response
  
# helpers

def get_url_as_readable_link_html(url: str):
  parsed_url = urlparse(url)
  full_valid_url = (parsed_url.scheme if parsed_url.scheme else 'https') + '://' + parsed_url.netloc + parsed_url.path
  readable_url = re.sub(r"^www\.", "", parsed_url.netloc)
  return '<a href="{full_valid_url}" target="_blank" noopener>{readable_url}</a>'.format(full_valid_url=full_valid_url, readable_url=readable_url)

def json_or_html_response(request: Request, authenticated: bool, data: any, status_code: int = 200, title: str = None, content: str = None, list_items: list[str] = None):
  if 'json' in request.headers.get('Accept'):
    return JSONResponse(data, status_code=status_code)
  else:
    response = get_html_response(title=title, status_code=status_code, content=content, list_items=list_items, authenticated=authenticated)
    return response

def add_following_html():
  form_html = """
    <form action="/following/add" method="POST" autocomplete="off">
      <label for="post">Add a URL to follow</label><br>
      <input type="url" id="url" name="url" value="" placeholder="https://example.com"><br><br>
      <input type="submit" value="Add">
    </form>
  """
  return form_html

def get_create_post_html():
  form_html = """
    <form id="create_post" action="/posts/create" method="POST" autocomplete="off">
      <label for="post">Create a post</label><br>
      <textarea id="text" name="text" form="create_post" value="" placeholder="Write something..."></textarea><br><br>
      <input type="submit" value="Post">
    </form>
    <hr/>
  """
  return form_html

def get_html_response(title: str, status_code: int = 200, content: str = None, list_items: list[str] = None, authenticated: bool = False):
  head_html = '<head><title>' + title + '</title><link rel="stylesheet" type="text/css" href="style.css" /></head>'
  page_title_html = "<h1>" + title + "</h1>"
  content_html = "<p>" + content + "</p>" if content else ""
  list_html = '<ul>' + ''.join(list(map(lambda item: "<li>" + item + "</li>", list_items))) + '</ul>' if list_items else ""
  link_to_feed_html = '<a href="/">Feed</a>' if authenticated else ''
  link_to_posts_html = '<a href="/posts">Posts</a>'
  link_to_following_html = '<a href="/following">Following</a>'
  link_to_followers_html = '<a href="/followers">Followers</a>'
  links_html = '<nav>Links: ' + link_to_feed_html + ' ' + link_to_posts_html + ' ' + link_to_following_html + ' ' + link_to_followers_html + '</nav>'
  html = "<html>" + head_html + "<body>" + page_title_html + content_html + list_html + "<hr/>" + links_html + "</body></html>"
  response = HTMLResponse(content=html, status_code=status_code)
  response.init_headers({'content-length': str(len(html))})
  return response

def get_readable_datetime(time):
  return datetime.datetime.fromtimestamp(int(time)/1000.0).strftime('%a %d %b %Y, %H:%M')

async def read_file(file_name: str):
  if (os.getenv('DETA_RUNTIME')):
    deta  = Deta(os.getenv('DETA_PROJECT_KEY'))
    deta_drive = deta.Drive('chit')
    res = deta_drive.get(file_name)
    file_contents = res.read() if res else b''
    if res and res.close:
      res.close()
    return file_contents.decode('utf8')
  else:
    try:
      with open(file_name,"r+t") as readable_file:
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
    file_name = deta_drive.put(file_name, data=new_data, content_type='text/plain')
    return file_name
  else:
    with open(file_name,"r+t") as writable_file:
      writable_file.write(new_data)
      writable_file.close()
      return file_name