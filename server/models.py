from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.ext.associationproxy import association_proxy

from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    serialize_rules = (
        "-recipes.user",
        "-_password_hash",
    )

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    _password_hash = db.Column(db.String)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship("Recipe", backref="user", cascade="all, delete-orphan")
    user_recipes = association_proxy("recipes", "user")

    @hybrid_property
    def password_hash(self):
        raise AttributeError("Password may not be viewed.")

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode("utf-8"))
        self._password_hash = password_hash.decode("utf-8")

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode("utf-8"))

    @validates("username")
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username must be present")
        return username

    def __repr__(self):
        return f"<User {self.username}>"


class Recipe(db.Model, SerializerMixin):
    __tablename__ = "recipes"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    @validates("title")
    def validate_title(self, key, title):
        if not title:
            raise ValueError("Title must be present")
        return title

    @validates("instructions")
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError(
                "Instructions must be present and at least 50 characters long"
            )
        return instructions

    def __repr__(self):
        return f"<Recipe {self.title}  instructions: {self.instructions}>"
