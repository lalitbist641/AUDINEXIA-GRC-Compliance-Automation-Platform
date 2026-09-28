from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
# storage_uri defaults to in-memory, which is fine for this single-process
# dev deployment -- same documented limitation as everything else in this
# codebase that hasn't yet moved to a shared backing store (see the old
# in-memory JWT blocklist this phase replaces).
limiter = Limiter(key_func=get_remote_address)
