import os
import re
import time
import datetime
import requests
import secrets
from urllib.parse import urlparse
from fastapi import FastAPI, Request, Depends, Security, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, PlainTextResponse, Response
from fastapi.security import APIKeyCookie
from colorhash import ColorHash
from pydantic import BaseModel
from deta import Deta


class Post(BaseModel):
    text: str
    time: int
    url: str


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
        print(e)
        return False


@app.get('/set-password/{password}', tags=["authentication"], response_class=RedirectResponse, responses={307: {"description": "Successfully saved password as cookie and redirected"}})
@app.get('/set-password/{password}/{old_password}', tags=["authentication"], response_class=RedirectResponse, responses={307: {"description": "Successfully saved password as cookie and redirected"}})
async def set_password(request: Request, password: str, old_password: str = '', authenticated: bool = Depends(is_authenticated)):
    prev_password = await read_file('password.txt')
    if old_password == prev_password:
        await write_file('password.txt', new_data=password)
        response = RedirectResponse('/')
        response.set_cookie('password', password, max_age=1000 *
                            60*60*24*30, samesite='strict', httponly=True)
        return response
    else:
        return await html_or_raw_response(
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
    response.set_cookie('password', password, max_age=1000 *
                        60*60*24*30, samesite='strict', httponly=True)
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
        normalized_following_url = (
            following_url_parsed.scheme if following_url_parsed.scheme else 'https') + '://' + following_url_parsed.netloc
        try:
            response = requests.get(normalized_following_url + '/posts',
                                    allow_redirects=False, timeout=5, headers={'Accept': 'text/plain'})
            if str(response.status_code)[0] != '2':
                raise Exception("Unable to get posts for a URL: " +
                                str(normalized_following_url))
            posts_for_url = get_posts_list_from_raw_file(
                response.text, normalized_following_url)
            posts += posts_for_url
        except Exception as e:
            print(e)
    posts.sort(reverse=True, key=lambda p: p.get("time"))
    list_items_html = list(map(lambda p: get_post_item_html(
        p.get('url'), p.get('text'), p.get('time'), current_url=normalized_current_url
    ), posts))
    try:
        content_html = (get_create_post_html(
            normalized_current_url) if authenticated else '')
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data=posts,
            status_code=200,
            title='Feed',
            content=content_html,
            list_items=list_items_html
        )
    except Exception as e:
        print(e)
        return PlainTextResponse('', 500)


@app.get('/posts', tags=["posts"], response_model=list[Post], responses={200: {"description": "Successfully got posts"}})
async def get_posts(request: Request, authenticated: bool = Depends(is_authenticated)):
    try:
        current_url = urlparse(request.url._url)
        normalized_current_url = current_url.scheme + '://' + current_url.netloc
        post_file = await read_file('posts.txt')
        posts = get_posts_list_from_raw_file(post_file, normalized_current_url)
        if len(posts) < 1:
            raise Exception('No posts available')
        posts.sort(reverse=True, key=lambda p: p.get("time"))
        list_items_html = list(map(lambda p: get_post_item_html(
            p.get('url'), p.get('text'), p.get('time'), current_url=normalized_current_url
        ), posts))
        about = await get_variables()
        title = ('Posts by ' + str(about.get('name'))
                 ) if about and about.get('name') else 'Posts'
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data=post_file,
            status_code=200,
            title=title,
            list_items=list_items_html
        )
    except Exception as e:
        print(e)
        return await html_or_raw_response(
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
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data=None,
            status_code=401,
            title='Not authorized',
            content='You do not have permission to create a post',
        )
    post = {
        'time': round(time.time() * 1000),
        'text': text,
    }
    await write_file('posts.txt', new_lines=[get_raw_post_from_post(post)])
    current_url = urlparse(request.url._url)
    normalized_current_url = current_url.scheme + '://' + current_url.netloc
    await notify_other_sites_of_mentions_in_post(post_id=post.get('time'), post_text=post.get('text'), current_url=normalized_current_url)
    return RedirectResponse('/', status_code=303)


@app.get('/posts/{post_id}', tags=["posts"], response_model=Post, responses={200: {"description": "Successfully got post", "model": Post}})
async def get_post(post_id: int, request: Request, authenticated: bool = Depends(is_authenticated)):
    try:
        current_url = urlparse(request.url._url)
        normalized_current_url = current_url.scheme + '://' + current_url.netloc
        posts_file = await read_file('posts.txt')
        post = get_post_by_id_from_raw_file(
            post_id=post_id, raw_file=posts_file)
        raw_post = get_raw_post_from_post(post)
        about = await get_variables()
        title = ('Post by ' + str(about.get('name'))
                 ) if about and about.get('name') else 'Post'
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data=raw_post,
            status_code=200,
            title=title,
            list_items=[get_post_item_html(
                url=normalized_current_url, text=post.get('text'), time=post.get('time'), current_url=normalized_current_url)]
        )
    except Exception as e:
        print(e)
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=500,
            title='Cannot get post',
            content='This post doesn\'t appear to be available. You may have the wrong address, or it may have been deleted.'
        )


@app.get('/following', tags=["following"], response_model=list[str])
async def get_following(request: Request, authenticated: bool = Depends(is_authenticated)):
    try:
        following_file = await read_file('following.txt')
        following = following_file.splitlines()
        if len(following) < 1:
            raise Exception('Not following any URLs')
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data=following_file,
            status_code=200,
            title='Following',
            content=add_following_html() if authenticated else None,
            list_items=list(map(lambda f: get_url_avatar_html(
                f) + get_url_as_readable_link_html(f), following)),
        )
    except Exception as e:
        print(e)
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=200,
            title='Following',
            content=(add_following_html() if authenticated else '') +
            '<p>Not following any URLs</p>',
        )


@app.post('/following/add', tags=["following"], response_model=bool, responses={303: {"description": "Successfully added URL as follower and redirected", "model": bool}, 401: {"description": "Unauthorized", "model": bool}, 405: {"description": "Unable to follow URL", "model": bool}})
async def follow_another_url(request: Request, url: str = Form(), authenticated: bool = Depends(is_authenticated)):
    if not authenticated:
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=401,
            title='Not authorized',
            content='You do not have permission to follow on behalf of this URL',
        )
    try:
        url_to_follow = urlparse(re.sub(r"^(?!https?\:\/\/)", "https://", url))
        normalized_url_to_follow = (
            url_to_follow.scheme if url_to_follow.scheme else 'https') + '://' + url_to_follow.netloc
        await write_file('following.txt', new_lines=[url])
        current_url = urlparse(request.url._url)
        normalized_current_url = current_url.scheme + '://' + current_url.netloc
        response_add_follower = requests.post(normalized_url_to_follow + '/followers/add', data={
                                              "url": normalized_current_url}, allow_redirects=False)
        did_add_follower = str(response_add_follower.status_code)[0] == '2'
        return RedirectResponse('/following?confirmed=' + str(did_add_follower).lower(), status_code=303)
    except:
        return await html_or_raw_response(
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
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data=followers_file,
            status_code=200,
            title='Followers',
            list_items=list(map(lambda f: get_url_avatar_html(
                f) + get_url_as_readable_link_html(f), followers)),
        )
    except:
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=200,
            title='Followers',
            content='Not followed by any URLs. See the <a href="/protocol">protocol</a> to learn how to add your site as a follower.',
        )


@app.post('/followers/add', tags=["followers"], responses={200: {"description": "Successfully added URL as a follower", "class": JSONResponse}, 405: {"description": "Not allowed to add URL as a follower", "class": JSONResponse}})
async def add_follower(request: Request, url: str = Form(), authenticated: bool = Depends(is_authenticated)):
    try:
        current_url = urlparse(request.url._url)
        requesting_url = urlparse(
            re.sub(r"^(?!https?\:\/\/)", "https://", url))
        normalized_requesting_url = (
            requesting_url.scheme if requesting_url.scheme else 'https') + '://' + requesting_url.netloc
        response = requests.get(normalized_requesting_url + '/following',
                                allow_redirects=False, headers={'Accept': 'text/plain'})
        if str(response.status_code)[0] != '2':
            raise Exception("Unable to get following list for this URL")
        following: list[str] = []
        for line in response.text.splitlines():
            parsed_url = urlparse(line)
            following.append(
                (parsed_url.scheme if parsed_url.scheme else 'https') + '://' + parsed_url.netloc)
        following_index: int = following.index(
            current_url.scheme + '://' + current_url.netloc)
        if following_index < 0:
            raise Exception(
                "The current URL is not in the following list for the provided URL")
        await write_file('followers.txt', new_lines=[normalized_requesting_url])
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=200,
            title='Follower URL added successfully',
        )
    except:
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=405,
            title='Cannot add follower',
            content='The <code>/following</code> file at the provided URL must include this URL'
        )


@app.get('/mentions', tags=["mentions"], response_model=list[Post], responses={200: {"description": "Successfully got mentions"}, 401: {"description": "Unauthorized"}})
async def get_posts(request: Request, authenticated: bool = Depends(is_authenticated)):
    if not authenticated:
        return await html_or_raw_response(
            request=request,
            authenticated=authenticated,
            data='',
            status_code=401,
            title='Unauthorized',
            content='You must be authorized to view mentions'
        )
    try:
        current_url = urlparse(request.url._url)
        normalized_current_url = current_url.scheme + '://' + current_url.netloc
        mentions_file = await read_file('mentions.txt')
        mentions = get_posts_list_from_raw_file(mentions_file)
        if len(mentions) < 1:
            raise Exception('No mentions available')
        mentions.sort(reverse=True, key=lambda m: m.get("time"))
        list_items_html = list(map(lambda m: get_post_item_html(
            m.get('url'), m.get('text'), m.get('time'), current_url=normalized_current_url
        ), mentions))
        about = await get_variables()
        title = ('Mentions of ' + str(about.get('name'))
                 ) if about and about.get('name') else 'Mentions'
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data=mentions_file,
            status_code=200,
            title=title,
            list_items=list_items_html
        )
    except Exception as e:
        print(e)
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=200,
            title='Mentions',
            content='No mentions available',
        )


@app.post('/mentions/add', tags=["mentions"], responses={200: {"description": "Successfully added URL as a mention", "class": JSONResponse}, 405: {"description": "Not allowed to add URL as a mention", "class": JSONResponse}})
async def add_mention(request: Request, post_url: str = Form(), authenticated: bool = Depends(is_authenticated)):
    try:
        response = requests.get(post_url,
                                allow_redirects=False, headers={'Accept': 'text/plain'})
        # got to here
        if str(response.status_code)[0] != '2':
            raise Exception("Unable to get the post for this URL")
        parsed_requesting_site_url = urlparse(post_url)
        normalized_requesting_site_url = (
            parsed_requesting_site_url.scheme if parsed_requesting_site_url.scheme else 'https') + '://' + parsed_requesting_site_url.netloc
        posts = get_posts_list_from_raw_file(
            response.text, normalized_requesting_site_url)
        if len(posts) != 1:
            raise Exception('The URL provided did not link to a valid post')
        post = posts[0]
        if str(post.get('time')) not in post_url:
            raise Exception(
                'The ID of the post at the proided URL did not match the ID in the URL')
        post['text'] = '>' + post_url + '\n' + post.get('text')
        await write_file('mentions.txt', new_lines=[get_raw_post_from_post(post)])
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=200,
            title='Mention added successfully',
        )
    except Exception as e:
        print(e)
        return await html_or_raw_response(
            request,
            authenticated=authenticated,
            data='',
            status_code=405,
            title='Cannot add mention',
            content='The <code>/following</code> file at the provided URL must include this URL'
        )


@app.get('/about', tags=["about"], response_class=HTMLResponse, status_code=200, responses={200: {"description": "Successfully got about"}})
async def get_about(request: Request, saved: bool = False, authenticated: bool = Depends(is_authenticated)):
    response = await get_page_for_file(
        file_name='about.txt',
        description='<p>Add your profile information in the format <code>name = John Smith</code>. The supported profile fields are: </p><ul><li><code>name</code> – your name, or the name for this site</li><li><code>avatar</code> – the file path of your avatar image on your server</li></ul>',
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
    try:
        style_file = await read_file('style.css', force_local=False)
        if not style_file or len(style_file) < 1:
            style_file = await read_file('style.css', force_local=True)
        style_response = PlainTextResponse(style_file, status_code=200)
        return style_response
    except:
        return PlainTextResponse('', status_code=404)


@app.get('/avatar', tags=["avatar"], response_class=Response, status_code=200, responses={200: {"description": "Successfully got avatar"}})
async def get_style():
    about = await get_variables()
    avatar_file_path = about.get('avatar')
    try:
        if not avatar_file_path or len(avatar_file_path) < 1:
            raise Exception('No avatar file')
        avatar_file = await read_file(file_name=avatar_file_path, force_local=False, force_raw=True)
        if len(avatar_file) < 1:
            raise Exception('No avatar file contents')
        file_type = 'image/' + avatar_file_path.split('.').pop()
        return Response(avatar_file, status_code=200, media_type=file_type, headers={'Cache-Control': 'max-age=604800'})
    except Exception as e:
        print(e)
        return PlainTextResponse('', status_code=404)


# helpers


def get_post_by_id_from_raw_file(post_id: int, raw_file: str, url: str = ''):
    posts_in_parts = re.findall(
        r"\[(" + str(post_id) + r")\]\n((?:.|\n)+?)(?=(?:\n\n*\[[0-9]+?\]|\n\n\Z))", raw_file, flags=re.MULTILINE)
    post = None
    for post in posts_in_parts:
        post = {
            "url": url,
            "time": int(post[0]),
            "text": post[1],
        }
    return post


def get_raw_post_from_post(post: dict):
    raw_post = ''
    raw_post += '[' + str(post.get('time')) + ']\n'
    raw_post += str(post.get('text'))
    raw_post += '\n\n'
    return raw_post


def get_posts_list_from_raw_file(raw_file: str, url: str = ''):
    posts_in_parts = re.findall(
        r"\[([0-9]+?)\]\n((?:.|\n)+?)(?=(?:\n\n*\[[0-9]+?\]|\n\n\Z))", raw_file, flags=re.MULTILINE)
    posts_list: list[dict] = []
    for post in posts_in_parts:
        time: int = int(post[0])
        text: str = post[1]
        if text.startswith('>https://') or text.startswith('>http://'):
            post_url = text.splitlines()[0][1:].strip()
            parsed_post_url = urlparse(post_url)
            site_url_normalized = (
                parsed_post_url.scheme if parsed_post_url.scheme else 'https') + '://' + parsed_post_url.netloc
            url = site_url_normalized
            text = text.replace(text.splitlines()[0], '')
        post_object = {
            "url": url,
            "time": time,
            "text": text,
        }
        if url and time and text and len(text) > 0:
            posts_list.append(post_object)
    return posts_list


def get_post_item_html(url: str, text: str, time: int, current_url: str):
    formatted_text = get_text_with_linked_urls_html(get_text_with_linked_mentions_html(
        get_text_with_basic_styling_html(text), current_url))
    return get_url_avatar_html(url) + "<div><div>" + get_url_as_readable_link_html(url) + " on " + get_readable_datetime_linked_html(time=time, url=url + '/posts/' + str(time)) + "</div><pre>" + formatted_text + "</pre></div>"


def get_url_avatar_html(url: str):
    parsed_url = urlparse(url)
    url_normalized = (
        parsed_url.scheme if parsed_url.scheme else 'https') + '://' + parsed_url.netloc
    potential_avatar_url = url_normalized + '/avatar'
    color = ColorHash(url_normalized).hex
    readable_url = re.sub(r"^www\.", "", parsed_url.netloc)
    initials = readable_url[0] if len(url) > 0 else ''
    return '<span class="avatar" style="--data-initials: \'{initials}\'; --data-color: {color}; --data-avatar-url: url(\'{potential_avatar_url}\')"></span>'.format(initials=initials, color=color, potential_avatar_url=potential_avatar_url)


def get_url_as_readable_link_html(url: str):
    parsed_url = urlparse(url)
    full_valid_url = (parsed_url.scheme if parsed_url.scheme else 'https') + \
        '://' + parsed_url.netloc + parsed_url.path
    readable_url = re.sub(r"^www\.", "", parsed_url.netloc)
    return '<a href="{full_valid_url}" target="_blank" noopener>{readable_url}</a>'.format(full_valid_url=full_valid_url, readable_url=readable_url)


async def html_or_raw_response(request: Request, authenticated: bool, data: any, status_code: int = 200, title: str = None, content: str = None, list_items: list[str] = None):
    if is_server_request(request):
        response = PlainTextResponse(data, status_code=status_code)
        return response
    else:
        response = await get_html_response(title=title, status_code=status_code,
                                           content=content, list_items=list_items, authenticated=authenticated)
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


async def get_html_response(title: str, status_code: int = 200, content: str = None, list_items: list[str] = None, authenticated: bool = False):
    about = await get_variables()
    avatar_path: str = about.get('avatar')
    head_html = '<head><title>' + title + '</title>' + \
        '<link rel="stylesheet" type="text/css" href="/style.css" />' + \
        ('<link rel="icon" type="image/'+avatar_path.split('.').pop()+'" href="/avatar"/>' if avatar_path else '') + \
        '<meta name="viewport" content="width=device-width, initial-scale=1.0" /></head>'
    page_title_html = "<h1>" + title + "</h1>"
    content_html = "<p>" + content + "</p>" if content else ""
    list_html = '<ul>' + ''.join(list(map(lambda item: "<li>" +
                                 item + "</li>", list_items))) + '</ul>' if list_items else ""
    link_to_feed_html = '<a href="/">Feed</a>' if authenticated else ''
    link_to_mentions_html = '<a href="/mentions">Mentions</a>' if authenticated else ''
    link_to_posts_html = '<a href="/posts">Posts</a>'
    link_to_following_html = '<a href="/following">Following</a>'
    link_to_followers_html = '<a href="/followers">Followers</a>'
    link_to_about_html = '<a href="/about">About</a>'
    link_to_protocol_html = '<a href="/protocol">Protocol</a>'
    links_html = '<nav>' + link_to_feed_html + ' ' + link_to_mentions_html + ' ' + link_to_posts_html + ' ' + link_to_following_html + \
        ' ' + link_to_followers_html + ' ' + link_to_about_html + \
        ' ' + link_to_protocol_html + '</nav>'
    html = "<html>" + head_html + "<body>" + links_html + "<hr/>" + \
        page_title_html + content_html + list_html + "</body></html>"
    response = HTMLResponse(content=html, status_code=status_code)
    return response


def get_readable_datetime_linked_html(url: str, time: int):
    return '<a href="'+url+'">'+get_readable_datetime(time)+'</a>'


def get_readable_datetime(time: int):
    return datetime.datetime.fromtimestamp(int(time)/1000.0).strftime('%a %d %b %Y, %H:%M')


async def read_file(file_name: str, force_local: bool = False, force_raw: bool = False):
    if (os.getenv('DETA_RUNTIME')) and force_local != True:
        deta = Deta(os.getenv('DETA_PROJECT_KEY'))
        deta_drive = deta.Drive('chit')
        res = deta_drive.get(file_name)
        file_contents = res.read() if res else b''
        if res and res.close:
            res.close()
        return file_contents.decode('utf8') if not force_raw else file_contents
    else:
        try:
            with open(file_name, "rt" if not force_raw else "rb") as readable_file:
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
        deta = Deta(os.getenv('DETA_PROJECT_KEY'))
        deta_drive = deta.Drive('chit')
        file_name = deta_drive.put(file_name, data=new_data.encode(
            'utf8'), content_type='text/plain')
        return file_name
    else:
        with open(file_name, "w+t") as writable_file:
            writable_file.write(new_data)
            writable_file.close()
            return file_name


async def get_update_handler_for_file(file_name: str, data: str, request: Request, authenticated: bool):
    label = file_name.split('.')[0]
    if not authenticated:
        return await html_or_raw_response(
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
        return await html_or_raw_response(
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
        return await html_or_raw_response(
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
            page_list_html = filter(lambda v: v != None, list(map(lambda v: None if v[0].startswith('_') else (
                '<strong>' + v[0].capitalize() + '</strong>: ' + get_text_with_linked_urls_html(v[1])), variables.items())))
        else:
            current_url = urlparse(request.url._url)
            normalized_current_url = current_url.scheme + '://' + current_url.netloc
            formatted_file = get_text_with_linked_urls_html(get_text_with_linked_mentions_html(
                get_text_with_basic_styling_html(file), current_url=normalized_current_url))
            page_html = """
        <pre style="width: 100%;">{formatted_file}</pre>
      """.format(label=label, description=description, formatted_file=formatted_file)
            page_list_html = None
    return await html_or_raw_response(
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
            variables.update({line_parts[0].strip(): line_parts[1].strip()})
    return variables


def get_text_with_linked_urls_html(text: str):
    linked_text_html = re.sub(
        r"(?<!\>)(?<!\")(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)(?:[-a-zA-Z0-9()@:%_\+~#?&//=]+))",
        r'<a href="\1" target="_blank" noopener>\1</a>',
        text,
    )
    return linked_text_html


def get_text_with_linked_mentions_html(text: str, current_url: str):
    current_username = current_url.replace(
        'https://', '').replace('http://', '')
    linked_mentions_text_html = text.replace('@' + current_username, '<a href="' + current_url +
                                             '" target="_blank" noopener class="mention is-self">@' + current_username + '</a>')
    linked_mentions_text_html = re.sub(
        r"(?<!\>)(?<!\")@([-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}(?:\:[0-9]{1,4})?)",
        r'<a href="https://\1" target="_blank" noopener class="mention">@\1</a>',
        linked_mentions_text_html,
    )
    return linked_mentions_text_html


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


async def notify_other_sites_of_mentions_in_post(post_id: int, post_text: str, current_url: str):
    post_url = current_url + '/posts/' + str(post_id)
    current_username = current_url.replace(
        'https://', '').replace('http://', '')
    mentioned_usernames = re.findall(
        r"@([-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}(?:\:[0-9]{1,4})?)",
        post_text,
        re.MULTILINE,
    )
    for mentioned_username in mentioned_usernames:
        mentioned_url_parsed = urlparse('https://' + mentioned_username)
        if mentioned_url_parsed.netloc and len(mentioned_url_parsed.netloc) and mentioned_url_parsed.netloc != current_username:
            normalized_mentioned_url = (
                mentioned_url_parsed.scheme if mentioned_url_parsed.scheme else 'https') + '://' + mentioned_url_parsed.netloc
            try:
                response = requests.post(normalized_mentioned_url + '/mentions/add', data={
                    "post_url": post_url}, allow_redirects=False)
                if str(response.status_code)[0] != '2':
                    raise Exception(
                        'Failed to send mention to url: ' + normalized_mentioned_url)
            except Exception as e:
                print(e)
