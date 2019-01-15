from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Category, Base, CatalogItem, User

engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

user1 = User(name="Mary", email="mvdultseva@gmail.com")

session.add(user1)
session.commit()

category1 = Category(name="Soccer")

session.add(category1)
session.commit()

category2 = Category(name="Basketball")

session.add(category2)
session.commit()

category3 = Category(name="Baseball")

session.add(category3)
session.commit()

category4 = Category(name="Frisbee")

session.add(category4)
session.commit()

category5 = Category(name="Snowboarding")

CatalogItem1 = CatalogItem(name="Goggies", description="",
                           category=category5, user=user1)

session.add(CatalogItem1)
session.commit()

CatalogItem2 = CatalogItem(name="Snowboard", description="Best for any terrain and condition",
                           category=category5, user=user1)

session.add(CatalogItem2)
session.commit()

session.add(category5)
session.commit()

category6 = Category(name="Rock Climbing")

session.add(category6)
session.commit()

category7 = Category(name="Foosball")

session.add(category7)
session.commit()

category8 = Category(name="Skating")

session.add(category8)
session.commit()

category9 = Category(name="Hockey")

session.add(category9)
session.commit()


print("categories added")