from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.page1),
    path('page1submit', views.page2),
    path('page3.html', views.page3),
    path('page3submit', views.page4),
]