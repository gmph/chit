import re
import time
import datetime
import requests
import secrets
from urllib.parse import urlparse
from fastapi import FastAPI, Request, Depends, Security, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import APIKeyCookie
from pydantic import BaseModel

class Post(BaseModel):
  text: str
  time: int

password_cookie = APIKeyCookie(name="password", auto_error=False)

chit = FastAPI(
    title="chit",
    description="Chit is a self-hosted, distributed micro-social network",
    version="0.0.1",
    contact={
        "name": "Graham Macphee",
        "url": "https://grahammacphee.com",
    },
)


def is_authenticated(password: str = Security(password_cookie)):
  with open("password.txt","r") as password_file:
    if password:
      correct_password_bytes = password_file.readline().encode()
      current_password_bytes = password.encode("utf8")
      is_correct_password = secrets.compare_digest(
          current_password_bytes, correct_password_bytes
      )
    else:
      is_correct_password = False
    return is_correct_password

@chit.get('/auth/{password}', tags=["authentication"], response_class=RedirectResponse, responses={307: {"description": "Successfully saved password as cookie and redirected"}})
async def auth(password: str):
  response = RedirectResponse('/')
  response.set_cookie('password', password, max_age=1000*60*60*24*30, samesite='strict', httponly=True)
  return response

@chit.get('/', tags=["posts"], response_model=list[Post], responses={200: {"description": "Successfully got posts"}, 204: {"description": "No posts available", "model": None}})
async def get_posts(request: Request, authenticated: bool = Depends(is_authenticated)):
  try:
    with open("posts.txt","r") as posts_file:
      posts_raw = posts_file.read()
      posts_in_parts = re.findall(r"\[([0-9]*?)\]\n(.*?)\n",posts_raw, flags=re.MULTILINE)
      posts = []
      for post in posts_in_parts:
        posts.insert(0, {
          "time": int(post[0]),
          "text": post[1]
        })
      
      list_items_html = list(map(lambda p: 
        "<div>" + p.get("text") + "</div><div>" + get_readable_datetime(p.get("time")) + "</div>",
        posts
      ))
      return json_or_html_response(
        request, 
        data=posts, 
        status_code=200, 
        title='Posts', 
        content=get_create_post_html() if authenticated else None,
        list_items=list_items_html
      )
  except:
    return json_or_html_response(
      request, 
      data=[], 
      status_code=204, 
      title='Posts', 
      content='No posts available',
    )

@chit.get('/posts', tags=["posts"], response_class=RedirectResponse, responses={307: {"description": "Successfully redirected"}})
async def redirect_to_get_posts():
  return RedirectResponse('/', status_code=301)

@chit.post('/posts/create', tags=["posts"], response_class=RedirectResponse, responses={401: {"class": JSONResponse}, 307: {"description": "Successfully posted and redirected", "class": RedirectResponse}})
async def create_post(request: Request, text: str = Form(), authenticated: bool = Depends(is_authenticated)):
  if not authenticated:
    return json_or_html_response(
      request, 
      data=None, 
      status_code=401, 
      title='Not authorized', 
      content='You do not have permission to create a post',
    )
  with open("posts.txt","a+") as posts_file:
    t = round(time.time() * 1000)
    posts_file.writelines([
      "[" + str(t) + "]\n",
      text,
      "\n\n",
    ])
    return RedirectResponse('/')

@chit.get('/posts/{post_id}', tags=["posts"], response_model=Post, responses={200: {"description": "Successfully got post", "model": Post}, 204: {"model": None}})
async def get_post(post_id: str, request: Request):
  with open("posts.txt","r") as posts_file:
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
      data=post, 
      status_code=200 if post else 204, 
      title=post.get('text'), 
      content=get_readable_datetime(post.get('time')),
    )

@chit.get('/following', tags=["following"], response_model=list[str])
async def get_following(request: Request):
  try:
    with open("following.txt","r") as following_file:
      following = following_file.readlines()
      return json_or_html_response(
        request, 
        data=following, 
        status_code=200, 
        title='Following', 
        list_items=following,
      )
  except:
    return json_or_html_response(
      request, 
      data=[], 
      status_code=204, 
      title='Following', 
      list_items='Not following any URLs',
    )

@chit.post('/following/add', tags=["following"], response_model=bool, responses={200: {"description": "Successfully added URL as follower", "model": bool}, 401: {}})
async def follow_another_url(url: str, request: Request, authenticated: bool = Depends(is_authenticated)):
  if not authenticated:
    return json_or_html_response(
      request, 
      data=None, 
      status_code=401, 
      title='Not authorized', 
      content='You do not have permission to follow on behalf of this URL',
    )
  with open("following.txt","a+") as following_file:
    following_file.writelines(['\n', url])
    return json_or_html_response(
        request, 
        data=True, 
        status_code=200, 
        title='Followed URL successfully', 
      )

@chit.get('/followers', tags=["followers"], response_model=list[str])
async def get_followers(request: Request):
  try:
    with open("followers.txt","r") as followers_file:
      followers = followers_file.readlines()
      return json_or_html_response(
        request, 
        data=followers, 
        status_code=200, 
        title='Followers', 
        list_items=followers,
      )
  except:
    return json_or_html_response(
      request, 
      data=[], 
      status_code=204, 
      title='Followers', 
      list_items='Not followed by any URLs',
    )

@chit.post('/followers/add', tags=["followers"], responses={200: {"description": "Successfully added URL as a follower", "class": JSONResponse}, 405: {"description": "Not allowed to add URL as a follower", "class": JSONResponse}})
async def add_follower(url: str, request: Request):
  try:
    current_url = urlparse(request.url._url)
    requesting_url = urlparse(re.sub(r"^(?!https?\:\/\/)", "https://", url))
    normalised_requesting_url = (requesting_url.scheme if requesting_url.scheme else 'https') + '://' + requesting_url.netloc
    response = requests.get(normalised_requesting_url + '/following', allow_redirects=False)
    if str(response.status_code)[0] != '2':
      raise Exception("Unable to get following list for this URL")
    following: list[str] =[]
    for line in response.text.splitlines():
      parsed_url = urlparse(line)
      following.append((parsed_url.scheme if parsed_url.scheme else 'https') + '://' + parsed_url.netloc)
    following_index: int = following.index(current_url.scheme + '://' + current_url.netloc)
    if following_index < 0:
      raise Exception("The current URL is not in the following list for the provided URL")
    with open("followers.txt","a+") as followers_file:
      followers_file.writelines([normalised_requesting_url, '\n'])
      return json_or_html_response(
        request, 
        data=True, 
        status_code=200, 
        title='Follower URL added successfully', 
      )
  except:
    return json_or_html_response(
        request, 
        data=True, 
        status_code=405, 
        title='Cannot add follower', 
        content='The /following file at the provided URL must include this URL'
      )
  
# helpers

def json_or_html_response(request: Request, data: any, status_code: int = 200, title: str = None, content: str = None, list_items: list[str] = None):
  if 'json' in request.headers.get('Accept'):
    return JSONResponse(data, status_code=status_code)
  else:
    return get_html_response(title=title, status_code=status_code, content=content, list_items=list_items)

def get_create_post_html():
  form_html = """
    <form action="/posts/create" method="POST" autocomplete="off">
      <label for="post">Create a post</label><br>
      <input type="text" id="post" name="text" value="" placeholder="Write something..."><br><br>
      <input type="submit" value="Post">
    </form>
  """
  return form_html

def get_html_response(title: str, status_code: int = 200, content: str = None, list_items: list[str] = None):
  head_html = "<head><title>" + title + "</title></head>"
  title_html = "<h2>" + title + "</h2>"
  content_html = "<p>" + content + "</p>" if content else ""
  list_html = '<ul>' + ''.join(list(map(lambda item: "<li>" + item + "</li>", list_items))) + '</ul>' if list_items else ""
  html = "<html>" + head_html + "<body>" + title_html + content_html + list_html + "</body></html>"
  return HTMLResponse(content=html, status_code=status_code)

def get_readable_datetime(time):
  return datetime.datetime.fromtimestamp(int(time)/1000.0).strftime('%a %d %b %Y, %H:%M')