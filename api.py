#!/usr/bin/env python
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask.ext.sqlalchemy import SQLAlchemy #needed for db
from flask.ext.httpauth import HTTPBasicAuth #needed for authentication
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from flask.ext.restful import Api, Resource, reqparse, fields, marshal


# initialization
app = Flask(__name__, static_url_path = "")
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite' #db file
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True #commit session when app context is torn down

# extensions
db = SQLAlchemy(app)
api = Api(app)
auth = HTTPBasicAuth()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True) #column for user id
    username = db.Column(db.String(32), index=True) #column for username
    password_hash = db.Column(db.String(64)) #column for password
    posts = db.relationship('Post', backref = 'author', lazy = 'dynamic') #user relationship with post
    comments = db.relationship('Comment', backref = 'author', lazy = 'dynamic') #user relationship with comment

    def hash_password(self, password): #password hashing
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password): #verifying password
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user
		
class Post(db.Model): #table for post
    id = db.Column(db.Integer, primary_key = True) #column for post id
    title = db.Column(db.String(50), index = True, unique = True) #column for post title
    body = db.Column(db.String(140)) #column for post body
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) #column for post user
    comments = db.relationship('Comment', backref = 'status', lazy = 'dynamic') #post relationship with comment

class Comment(db.Model): #table for comment
    id = db.Column(db.Integer, primary_key = True) #column for comment id
    body = db.Column(db.String(140)) #column for comment body
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) #column for comment user
    post_id = db.Column(db.Integer, db.ForeignKey('post.id')) #column for comment post


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

class UserAPI(Resource):
    
    def get(self, id):
        decorators = [auth.login_required]
        user = User.query.get(id)
        if not user:
            cols = ['id', 'username']
            user = User.query.all()
            result = [{col: getattr(d, col) for col in cols} for d in user]
            return jsonify(users=result)

        return {'id': user.id,'username': user.username}

    def delete(self, id):
        decorators = [auth.login_required]
        user = User.query.get(id) #get user to be deleted
        if not user.username is not user.id:
            return { 'message': 'invalid credentials. cannot delete'}
        if not user: 
            return user_notexist()
        db.session.delete(user) #delete user in db
        db.session.commit()
        return { 'username' : user.username, 'result': 'user deleted' }, 200

    def post (self, id = None):
        username = request.json.get('username') #input username
        password = request.json.get('password') #input password
        if username is None or password is None: #missing arguments
            return {'message': 'missing arguments' }, 400
        if User.query.filter_by(username=username).first() is not None:
            return {'message': 'user already exists' }, 400 # existing user
        user = User(username=username)
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()
        return {'username': user.username, 'id': user.id}, 201

api.add_resource(UserAPI, '/api/users/<int:id>', endpoint = 'user')


class PostAPI(Resource):
    decorators = [auth.login_required]

    def post(self, uid, id = None):
        user = User.query.get(uid) #get user who will post
        title = request.json.get('title')
        body  = request.json.get('body')
        p = Post(title = request.json.get('title'), body  = request.json.get('body'), author=user) #input title and body of post
        if p.title is None or p.body is None: #missing arguments
            return {'message': 'missing arguments' }, 400
        if not user: #if user does not exist
            return {'message' : 'user does not exist'}, 404
        if Post.query.filter_by(title=title).first() is not None:
            return {'message': 'post already exists' }, 400 #posts already exist
        db.session.add(p) #add post to db
        db.session.commit()
        return { p.author.username : { 'post': p.title, 'body': p.body}}, 201

    def get(self, uid, id):
        user = User.query.get(uid) #get user who posted
        post = Post.query.get(id) #get post to be read
        
        if not user: #if user does not exist
            return {'message' : 'user does not exist'}, 404
        if not post:  #if post does not exist
            cols = ['id', 'title', 'body', 'user_id']
            post = Post.query.all() #get all posts of user
            result = [{col: getattr(d, col) for col in cols} for d in post]
            return jsonify(posts=result)
        
        return {post.author.username : { 'post': post.title, 'body': post.body}}

    def put(self, uid, id):
        user = User.query.get(uid) #get user who posted
        post = Post.query.get(id) #get post to be updated
        if not user: #if user does not exist
            return {'message' : 'user does not exist'}, 404
        if not post:  #if post does not exist
            return {'message': 'post does not exist' }, 404
        if not request.json: #if input is not json
            return {'message':'bad request'}, 400
        if user.id is not post.author.id: #if user is not the one who posted
            return {'message':'not allowed'}, 405
        if 'title' in request.json and type(request.json.get('title')) != unicode: #if entered title is not unicode
            return {'message':'bad request'}, 400
        if 'body' in request.json and type(request.json.get('body')) is not unicode: #if entered body is not unicode
            return {'message':'bad request'}, 400
        post.title = request.json.get('title', post.title) #input updated title
        post.body = request.json.get('body', post.body) #input updated body
        db.session.commit() #update in dbs
        return { post.author.username : { 'post': post.title, 'body': post.body }}

    def delete(self, uid, id):
        user = User.query.get(uid) #get user who posted
        post = Post.query.get(id) #get post to be deleted
        if not user: #if user does not exist
            return {'message' : 'user does not exist'}, 404
        if not post:  #if post does not exist
            return {'message': 'post does not exist' }, 404
        if user.id is not post.author.id: #if user is not the one who posted
            return {'message':'not allowed'}, 405
        db.session.delete(post) #delete post in db
        db.session.commit()
        return { 'post': post.title, 'result': 'post deleted' }, 200

api.add_resource(PostAPI, '/api/users/<int:uid>/posts/<int:id>', endpoint='post')

class CommentAPI(Resource):
    decorators = [auth.login_required]

    def post(self, uid, pid, id = None):
        user = User.query.get(uid) #get user who will comment
        post = Post.query.get(pid) #get post to be commented
        c = Comment(body  = request.json.get('body'), status=post, author=user) #input comment
        if c.body is None: #missing arguments
            return {'message': 'missing arguments' }, 400
        if not user: #if user does not exist
            return {'message' : 'user does not exist'}, 404
        if not post:  #if post does not exist
            return {'message': 'post does not exist' }, 404
        db.session.add(c) #add comment to db
        db.session.commit()
        return { post.author.username : { post.title : { 'body': post.body, 'commented by': c.author.username, 'comment': c.body}}}, 201

    def get(self, uid, pid, id):
        user = User.query.get(uid) #get user who commented
        post = Post.query.get(pid) #get post commented
        comment = Comment.query.get(id) #get comment to be read
        if not user: #if user does not exist
            return {'message': 'user does not exist' }, 404
        if not post:  #if post does not exist
            return {'message': 'post does not exist' }, 404
        if not comment: #if comment does not exist
            cols = ['id', 'body', 'user_id', 'post_id']
            comment = Comment.query.filter_by(post_id=post.id) #get all comments of post
            result = [{col: getattr(d, col) for col in cols} for d in comment]
            return jsonify(comments=result)
        return { post.author.username : { post.title : { 'body': post.body, 'commented by': comment.author.username, 'comment': comment.body}}}

    def put(self, uid, pid, id):
        user = User.query.get(uid) #get user who commented
        post = Post.query.get(pid) #get post commented
        comment = Comment.query.get(id) #get comment to be updated
        if not comment: #if comment does not exist
            return comment_notexist()
        if not user: #if user does not exist
            return {'message': 'user does not exist' }, 404
        if not post:
            return {'message': 'post does not exist' }, 404
        if not request.json: #if input is not json
            return {'message':'bad request'}, 400
        if user.id is not comment.author.id: #if user is not the one who commented
            return {'message':'not allowed'}, 405
        if post.id is not comment.status.id: #if comment is not in the post or in different post
            return {'message':'bad request'}, 400
        if 'body' in request.json and type(request.json.get('body')) is not unicode: #if entered comment is not unicode
            return {'message':'bad request'}, 400
        comment.body = request.json.get('body', comment.body) #input updated comment
        db.session.commit() #update comment in db
        return { post.author.username : { post.title : { 'body': post.body, 'commented by': comment.author.username, 'comment': comment.body }}}

    def delete(self, uid, pid, id):
        user = User.query.get(uid) #get user who commented
        post = Post.query.get(pid) #get post commented
        comment = Comment.query.get(id) #get comment to be deleted
        if not user: #if user does not exist
            return {'message': 'user does not exist' }, 404
        if not post:
            return {'message': 'post does not exist' }, 404
        if not comment: #if comment does not exist
            return {'message': 'comment does not exist' }, 404
        if post.id is not comment.status.id: #if comment is not in the post or in different post
            return {'message':'bad request'}, 400
        db.session.delete(comment) #delete comment in db
        db.session.commit()
        return {'comment': comment.id, 'result': 'comment deleted' }
	
api.add_resource(CommentAPI, '/api/users/<int:uid>/posts/<int:pid>/comments/<int:id>', endpoint ='comment') #read specific comment

@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
