from sqlalchemy import Column, ForeignKey, Integer, String, DateTime, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable = False)
    email = Column(String(250), nullable = False)
    picture = Column(String(250))
    created_date = Column(DateTime, default=datetime.datetime.utcnow)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'email'        : self.email,
           'picture'      : self.picture,
           'created_date'   : self.created_date
       }

class Asset(Base):
    __tablename__ = 'asset'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable = False)
    activated = Column(String(10), nullable = False)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'activated'       : self.activated,
           'created_date'   : self.created_date,

       }


class OrderBook(Base):
    __tablename__ = 'orderbook'
   
    id = Column(Integer, primary_key=True)
    type = Column(String(250), nullable=False)
    ammount = Column(Integer, nullable=False)
    created_date = Column(DateTime, default=datetime.datetime.utcnow)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    asset_id = Column(Integer, ForeignKey('asset.id'))
    asset = relationship(Asset)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'type'         : self.type,
           'id'           : self.id,
           'ammount'      : self.ammount,
           'created_date'   : self.created_date,
           
       }

engine = create_engine('sqlite:///motoremparejamiento.db')

Base.metadata.create_all(engine)
