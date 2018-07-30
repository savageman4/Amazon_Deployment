from __future__ import unicode_literals
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.db import models
import bcrypt
import re #this imports regedit
from apps.user_dashboard.models import *


class User_Manager(models.Manager):
    
    def process_registration(self, errors, postData):

        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


        if User.objects.filter(emailAddress = postData['remail']):
            duplicate = True
        else:
        	duplicate=False

        if len(postData['rfname']) < 2:
            errors['rfname'] = "First name should be longer than 2 characters"
        elif len(postData['rfname']) == 0: #check to be sure first name was entered
            errors['rfname'] = "Please enter a first name"
        elif (postData['rfname']).isalpha == 1: #check to be sure that first name is alphabetic
            errors['rfname'] = "Last name must be alphabetic"
        elif len(postData['rlname']) == 0: #check to be sure last name was entered
            errors['rlname'] = "Please enter a last name"
        elif (postData['rlname']).isalpha == 1: #check to be sure that last name is alphabetic
            errors['rlname'] = "Last name must be alphabetic"
        elif len(postData['remail']) == 0: #check if email address was entered
            errors['remail'] = "Please enter an email address"
        elif duplicate is True: #check to see if email is already in the system
            errors['remail'] = "Your account is already present in our system"
        elif not EMAIL_REGEX.match(postData['remail']): #check to be sure there is an asterisk in email address
             errors['remail'] = "Email addresses must contain at least 1 asterisk!"
        elif len(postData['rpassword']) == 0:
             errors['rpassword'] = "Password must be entered" 
        elif len(postData['rpassword']) < 7:
             errors['rpassword'] = "Password must be at least 8 characters long"
        elif len(postData['rcpassword']) == 0:
             errors['rcpassword'] = "Confirm Password must be entered when registering"
        elif postData['rpassword'] != postData['rcpassword']:
             errors['rpassword'] = " Confirm password and Password do not match"

        return(errors)

    def process_edit(self, errors, postData):

        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


        if User.objects.filter(id = postData['e_id']):
            found = True
        else:
            found = False

        if len(postData['epassword']) == 0:
            password_check = False
        else:
            password_check = True


        if found == False:   
            errors['e_id'] = "Your account is not present in our system"
        elif len(postData['eemail']) == 0: #check if email address was entered
            errors['eemail'] = "Please enter an email address"
        elif not EMAIL_REGEX.match(postData['eemail']): #check to be sure there is an asterisk in email address
             errors['eemail'] = "Email addresses must contain at least 1 asterisk!"
        elif len(postData['efname']) < 2:
            errors['efname'] = "First name should be longer than 2 characters"
        elif len(postData['efname']) == 0: #check to be sure first name was entered
            errors['efname'] = "Please enter a first name"
        elif (postData['efname']).isalpha == 1: #check to be sure that first name is alphabetic
            errors['efname'] = "Last name must be alphabetic"
        elif len(postData['elname']) == 0: #check to be sure last name was entered
            errors['elname'] = "Please enter a last name"
        elif (postData['elname']).isalpha == 1: #check to be sure that last name is alphabetic
            errors['elname'] = "Last name must be alphabetic"
        elif len(postData['epassword']) < 7 and password_check == True:
             errors['epassword'] = "Password must be at least 8 characters long"
        elif len(postData['ecpassword']) == 0 and password_check == True:
             errors['ecpassword'] = "Confirm Password must be entered and be the same value as password when changing password"
        elif postData['epassword'] != postData['ecpassword'] and password_check == True:
             errors['epassword'] = " Confirm password and Password do not match"

        return(errors)        

    def process_login(self, errors, postData):

        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

        if User.objects.filter(emailAddress = postData['lemail']): #check for email in database
            user_found = True
            b = User.objects.get(emailAddress = postData['lemail'])
            print("created b user object using get in models.py process_login")
            print("Password = ", b.password)
        else:
            user_found = False
        print("********* user_found = " + str(user_found))
        if user_found is False: 
            errors['lemail']="Your email address is not in our system"
        elif not EMAIL_REGEX.match(postData['lemail']): #check to be sure there is an asterisk in email address
            errors['lemail'] = "Email addresses must contain at least 1 @ symbol!"
        elif len(postData['lpassword']) == 0:
            errors['lpassword'] = "Password must be entered" 
        elif len(postData['lpassword']) < 7:
            errors['lpassword'] = "Password must be at least 7 characters long"
        elif bcrypt.checkpw(postData['lpassword'].encode(), b.password.encode()):
            print ("Bcript did work")
        else:
            errors['lpassword'] = "Problem processing this login"

        print("Made it to Model Process_Login just before Return of errors")
        return(errors)

    def basic_validator(self, postData, function):  #the method that calls this should pass reqeust.POST as postData
        errors = {}
        if function == "registration":
            errors=User.objects.process_registration(errors, postData)
            return (errors)
        elif function == "login":
            errors = User.objects.process_login(errors, postData)
            return (errors)
        elif function == "add_user":
            errors = User.objects.process_registration(errors, postData)
            return (errors)
        elif function == "edit_user":
            errors = User.objects.process_edit(errors, postData)
            return (errors)
        else:
            errors['processing error in basic validator'] = "YES"
            return (errors)	

class Message_Manager(models.Manager):

	def basic_message_validator(self, postData, function):  #the method that calls this should pass reqeust.POST as postData

		return HttpResponse("Made it to basic_message_validator")

class Comment_Manager(models.Manager):
    
    def basic_comment_validator(self, postData, function):  #the method that calls this should pass reqeust.POST as postData
    	return HttpResponse("Made it to basic_comment_validator")


class User(models.Model):
    lastName = models.CharField(max_length=255)
    firstName = models.CharField(max_length=255)
    emailAddress = models.EmailField(max_length=100)
    password = models.CharField(max_length=100)
    user_level = models.IntegerField()
    comment = models.CharField(max_length=250, default="none")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = User_Manager()

class Message(models.Model):
    message = models.CharField(max_length=3000)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    msg_entered_by = models.ForeignKey(User, related_name = "messages")
    objects = Message_Manager()

class Comment(models.Model):
    comment = models.CharField(max_length=1000)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    cmnt_entered_by = models.ForeignKey(User, related_name = "user_comments")
    related_msg = models.ForeignKey(Message, related_name = "message_comments")
    objects = Comment_Manager()

