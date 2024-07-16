#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        json_data = request.get_json()


        if not json_data.get("username") or not json_data.get("password"):
            return {
                "errors": {
                    "username": "Username is required",
                    "password": "Password is required",
                }
            }, 422

        try:
            user = User(
                username=json_data["username"],
                image_url=json_data.get("image_url"),
                bio=json_data.get("bio"),
            )
            user.password_hash = json_data["password"]
            db.session.add(user)
            db.session.commit()
            session["user_id"] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio,
            }, 201
        except IntegrityError:
            db.session.rollback()
            return {"errors": {"username": "Username already taken"}}, 422


class CheckSession(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get("user_id")).first()
        if user:
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio,
            }, 200
        return {"errors": {"message": "Unauthorized"}}, 401


class Login(Resource):
    def post(self):
        json_data = request.get_json()
        username = json_data.get("username")
        password = json_data.get("password")

        if not username or not password:
            return {
                "errors": {
                    "username": "Username is required",
                    "password": "Password is required",
                }
            }, 422

        user = User.query.filter(User.username == username).first()
        if user and user.authenticate(password):
            session["user_id"] = user.id
            return {
                "id": user.id,
                "username": user.username,
                "image_url": user.image_url,
                "bio": user.bio,
            }, 200
        return {"errors": {"message": "Invalid username or password"}}, 401


class Logout(Resource):
    def delete(self):
        if session.get("user_id"):
            session.pop("user_id", None)
            return {}, 204
        return {"errors": {"message": "Unauthorized"}}, 401


class RecipeIndex(Resource):
    def get(self):
        user = User.query.filter(User.id == session.get("user_id")).first()
        if user:
            recipes = [recipe.to_dict() for recipe in Recipe.query.all()]
            return recipes, 200
        return {"errors": {"message": "Unauthorized"}}, 401

    def post(self):
        user = User.query.filter(User.id == session.get("user_id")).first()
        if user:
            json_data = request.get_json()
            try:
                recipe = Recipe(
                    title=json_data["title"],
                    instructions=json_data["instructions"],
                    minutes_to_complete=json_data["minutes_to_complete"],
                    user_id=user.id,
                )
                db.session.add(recipe)
                db.session.commit()
                return {
                    "title": recipe.title,
                    "instructions": recipe.instructions,
                    "minutes_to_complete": recipe.minutes_to_complete,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "image_url": user.image_url,
                        "bio": user.bio,
                    },
                }, 201
            except IntegrityError:
                db.session.rollback()
                return {"errors": {"message": "Unprocessable Entity"}}, 422
        return {"errors": {"message": "Unauthorized"}}, 401


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
