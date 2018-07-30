from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from time import gmtime, strftime
from django.utils.crypto import get_random_string
from django.db import models
import re  #this imports regedit
from apps.user_dashboard.models import *
import bcrypt

def index(request):  # for localhost:8000/users
    # return HttpResponse("Hi")
    return render(request, 'Input_and_Edit.html')

def process_reg(request):    # for localhost:8000/users/process_reg

    function = "registration"

    errors = User.objects.basic_validator(request.POST,function)
    
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags=key)
        request.session['signedin'] = "no"
        return redirect("/dashboard")

    a = User.objects.all()  #find out if this is the first user in the database. If so, make him or her the admin

    hashed_password = bcrypt.hashpw(request.POST['rpassword'].encode(), bcrypt.gensalt())

    if len(a) > 0:
        user_level = 1
    else:
        user_level = 9

    b = User.objects.create(lastName=request.POST['rlname'], firstName=request.POST['rfname'], emailAddress=request.POST['remail'], password=hashed_password, user_level=user_level)

    b.save()

    request.session['loginid'] = b.emailAddress
    request.session['user_level'] = b.user_level
    request.session['user_id'] = b.id

    return redirect("/dashboard/reg_success")    

def process_login(request):  #for localhost:8000/users/process_login
 
    function = "login"

    errors = User.objects.basic_validator(request.POST,function)

    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags=key)
            request.session['signedin'] = "no"
            return redirect("/dashboard")
    else:
        b = User.objects.get(emailAddress = request.POST['lemail'])
        request.session['loginid'] = b.emailAddress
        request.session['user_level'] = b.user_level
        request.session['user_id'] = b.id
        return redirect("/dashboard/login_success")

def edit_user(request, userid):

    b=User.objects.get(id=userid)   #get user who is being edited

    c=User.objects.get(id=request.session["user_id"])  #get user who is editing

    cmnts=User_Edit_Comment.objects.filter(edit_user=b)

    if c.user_level == 9 or c.id == b.id:
        context = {"user":b, "updater":c, "comments":cmnts}
        print("made it to edit_user")
        print("User data: ", b.firstName, b.lastName)
        return render(request, 'Edit.html', context)
    else:
        return redirect("/dashboard/" + str(b.id) + "/" + str(c.id) +"/issue_error")

def issue_error(request, edited, editor):

    errors={}
    errors['e.id'] = "You are not allowed to update another user's record - only your own"

    for key, value in errors.items():
        messages.error(request, value, extra_tags=key)

    return redirect("/dashboard/success")

def process_edit(request, userid):    # for localhost:8000/users/process_reg

    function = "edit_user"

    errors = User.objects.basic_validator(request.POST,function)
    
    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags=key)
        return redirect("/dashboard/" + str(userid) + "/edit_user")

    hashed_password = bcrypt.hashpw(request.POST['epassword'].encode(), bcrypt.gensalt())

    b = User.objects.get(id=userid)

    b.lastName = request.POST["elname"]
    b.firstName = request.POST["efname"]
    b.emailAddress = request.POST["eemail"]
    b.password = hashed_password

    if request.POST["eadmin"] == "Normal":
        b.user_level = 1
    else:
        b.user_level = 9

    b.save()

    if len(request.POST['ecomment']) > 1:
        c=User_Edit_Comment.objects.create(edit_comment=request.POST['ecomment'], edit_user=b)
        c.save()

    return redirect("/dashboard/reg_success")  

def process_noclick(request): #for localhost:8000/users/process_noclick

    return redirect("/dashboard")

def reg_success(request):  #for localhost:8000/users/reg_success

    return redirect("/dashboard/success")

def login_success(request):      #for localhost:8000/users/login_success

    return redirect("/dashboard/success")

def success(request):   #for localhost:8000/users/success
    print("success just before render of Displaying Blocks reg_login app")
    request.session['signedin'] = "yes"
    print(request.session['signedin'])

    userid=int(request.session['user_id'])

    b = User.objects.get(id=userid)

    context = {"users":User.objects.all(), "e_user":b}

    if b.user_level == 9:
        return render(request, 'Index.html', context)
    else:
        return render(request, 'Non_Admin_Index.html', context)

def new(request):

    b = User.objects.get(id=request.session['user_id'])

    context = {"updater":b}

    return render(request, 'Add.html', context ) 

def new_commit(request):

    function = "add_user"

    errors = User.objects.basic_validator(request.POST,function)

    if len(errors) > 0:
        for key, value in errors.items():
            messages.error(request, value, extra_tags=key)
            request.session['signedin'] = "no"
            return redirect("/dashboard")
    
    hashed_password = bcrypt.hashpw(request.POST['rpassword'].encode(), bcrypt.gensalt())

    if request.POST["radmin"] == "Normal":
        user_level = 1
    else:
        user_level = 9 

    b = User.objects.create(lastName=request.POST['rlname'], firstName=request.POST['rfname'], emailAddress=request.POST['remail'], password=hashed_password, user_level=user_level)
    b.save()

    if len(request.POST['rcomment']) > 1:
        c=User_Edit_Comment.objects.create(edit_comment=request.POST['rcomment'], edit_user=b)
        c.save()

    return redirect("/dashboard/success")  

def destroy(request, number):
    b = User.objects.get(id=number)
    b.delete()
    return redirect('/dashboard/success')   

def wall_index(request):  # for localhost:8000/users

    return render(request, 'Wall_Index.html', { "users":User.objects.all() })

def display_wall(request, e_userid, l_userid):

    u = User.objects.get(id = l_userid)  #user to whom this message is linked
    fn = u.firstName
    ln = u.lastName
    user_id = u.id

    v = User.objects.get(id =e_userid)  #user entered this message
    fn = v.firstName
    ln = v.lastName
    user_id = v.id

    context = { "messages":Message.objects.filter(msg_linked_to = User.objects.get(id=l_userid) ), "l_user":u, "e_user":v  }

    return render(request,'Wall_Content.html', context)

def add_message(request):

    userid=request.POST["add_msg_userid"] 

    u = User.objects.get(id = userid) #user to whom this message will be added

    v = User.objects.get(id = request.session["user_id"])

    m = Message.objects.create(message = request.POST["new_message_content"], msg_entered_by = v, msg_linked_to = u)

    m.save()

    return redirect("/dashboard/" + str(request.session["user_id"]) + "/" + str(userid) + "/wall_content")

def delete_comment(request):

    commentid=request.POST["delete_commentid"]
    userid=request.POST["delete_userid"]

    d = Comment.objects.get(id = commentid)
    d.delete()

    return redirect("/dashboard/" + str(request.session["user_id"]) + "/" + str(userid) + "/wall_content")

def add_comment(request):

    userid=request.POST["new_comment_userid"]
    messageid=request.POST["new_comment_messageid"]

    u = User.objects.get(id = userid) #get user to whom this comment is associated
    m = Message.objects.get(id=messageid)
    d = User.objects.get(id=request.session["user_id"]) #get user who entered this comment

    c = Comment.objects.create(wall_comment = request.POST["new_comment_content"], cmnt_entered_by = d, cmnt_linked_to = u, related_msg = m)
    c.save()

    return redirect("/dashboard/" + str(d.id) + "/" + str(u.id) + "/wall_content")

def show(request):    # for localhost:8000/users/process_reg
    return redirect("/dashboard")
 


     # return redirect("/dashboard/wall_index/" + str(userid) + "/content")