from django.conf.urls import url
from . import views        

# all urls must begin with "/login" per the main url.py file

urlpatterns = [
    url(r'^$', views.index),   # This is an empty string
    url(r'^process_reg$', views.process_reg),
    url(r'^process_login$', views.process_login),
    url(r'^process_noclick$', views.process_noclick),
    url(r'^reg_success$', views.reg_success),
    url(r'^login_success$', views.login_success),          
    url(r'^success$', views.success),
    url(r'^new$', views.new),
    url(r'^new/commit$', views.new_commit),
    url(r'^(?P<userid>\d+)/edit_user$', views.edit_user),
    url(r'^(?P<userid>\d+)/process_edit$', views.process_edit),
    url(r'^(?P<edited>\d+)/(?P<editor>\d+)/issue_error$', views.issue_error),
    url(r'^(?P<number>\d+)/destroy$', views.destroy),
    url(r'^wall_index$', views.wall_index),
    url(r'^content$', views.show),
    url(r'^(?P<e_userid>\d+)/(?P<l_userid>\d+)/wall_content$', views.display_wall),
    url(r'^store_message$', views.add_message), 
    url(r'^delete_comment$', views.delete_comment),
    url(r'^store_comment$', views.add_comment) 
]                  


