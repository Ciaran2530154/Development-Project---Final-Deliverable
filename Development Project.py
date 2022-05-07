#!/usr/bin/env python3
#import scapy and network library

import scapy.all as scapy
from pythonping import ping
import os
import subprocess
import socket
import argparse
#import tkinter GUI library 
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter.messagebox import showinfo


#import regular expressions

import re
import threading 
import collections
import logging
import sys
import time

#Global Variables


thread= None
stopped = True
subdomain = ''
startTime = time.time()
src_ip_dict = collections.defaultdict(list)
pingoutcome = StringVar() #pinger variable 

#database creation and selection, cursor definition

import sqlite3
with sqlite3.connect("networkforensic.db") as db:
    cursor = db.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS users(username TEXT NOT NULL, password TEXT NOT NULL);")
cursor.execute("SELECT * FROM users")

db.commit()



#TKInter GUI Settings, configuring ROOT early

root = tk.Tk()
root.configure(bg='light grey')










def registeruserbutton():
    registervalues = usernameregistry.get(), passwordregistry.get()
    registersql = 'INSERT INTO users VALUES (?,?)'

    registerscreen.withdraw()
    cursor.execute(registersql,registervalues)
    db.commit()
     

def loginuser():
    usernamesql = usernamelogin.get()
    pwdsql = passwordlogin.get()
    cursor.execute('SELECT * from users WHERE username="%s" and password="%s" '%(usernamesql, pwdsql))

    if cursor.fetchone():
        welcomemessage.set("Logged in, opening program..")
        


        loginscreen.withdraw()

        roottomainmenu()
        winMenu.deiconify()
    else:
        welcomemessage.set("Username or Password not recognized")
        
    db.commit()

def loginuserscreen():
    loginscreen.deiconify()

def registeruser():
    registerscreen.deiconify()


def get_ping():
    result = ping(entryform.get(), verbose=True)
    pingoutcome.set(result)



## Navigation Functions #####


## Root screen (login/register screen) navigation functions

def roottomainmenu():
    #Creation of window, definition of properties 
    root.withdraw()
    loginscreen.withdraw()


def logintoroot():
    loginscreen.withdraw()

def registertoroot():
    registerscreen.withdraw()


## Sub module / Main Menu  navigation functions

def maintoping():
    winMenu.withdraw()
    pingwindow.deiconify()

def pingtomain():
    pingwindow.withdraw()
    winMenu.deiconify()

def maintosniffer():
    root.withdraw()
    winMenu.withdraw()
    sniffer.deiconify()

def sniffertomain():
    sniffer.withdraw()
    winMenu.deiconify()
    global stopped
    stopped = False  ## Stops the Sniffer if the user leaves whilst it is running.


def maintoroot():
    winMenu.withdraw()
    root.deiconify()
    welcomemessage.set("Please Log Back In")

def arptomain():
    arpscanner.withdraw()
    winMenu.deiconify()

def maintoarp():
    winMenu.withdraw()
    arpscanner.deiconify()
    cleartext()


def maintotutorial():
    winMenu.withdraw()
    tutorialwindow.deiconify()

def tutorialtomain():
    winMenu.deiconify()
    tutorialwindow.withdraw()



    # Scapy Packet Sniff Functions and Classes

class scannermodule:
    def arptextscanner(func): #function to output gnome-terminal output to textbox for a easier, distinct visual output to the user
        def inner(inputStr): #inputstring format for this function
            try:
                arptextscanner.insert(INSERT, inputStr)
                return func(inputStr)
            except:
                return func(inputStr)
        return inner

    sys.stdout.write=arptextscanner(sys.stdout.write) #Outputs gnome-terminal STD out to "textbox arptextscanner"
    def Arp(self, ip):
        self.ip = ip
        print(ip) # Prints IP
        arp_r = scapy.ARP(pdst=ip) #the IP of the Destination of Packet 
        br = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') ## Broadcast frame is FF (hex mac address)
        request = br/arp_r
        answered, unanswered = scapy.srp(request, timeout=1)
        print('IP                    MAC') 
        print('_' * 37) # Print out 37 - Lines for visual clarity
        for i in answered:
            ip, mac = i[1].psrc, i[1].hwsrc #Corresponding MAC Address with IP 
            print(ip, '      ' + mac) # Prints the IP & MAC address header
            print('-' * 37) #Writes the - 37 times in order to form a proper table

arp = scannermodule() # Instanciates the scannermodule class for use in the ARP function below

def cleartext():
   arptextscanner.delete("1.0","end") ## Clears ARP text console on entry.

def runarp(): ##Special function made for above class, to run, commit to a scan then print to a texbox on the window.
    arp.Arp("192.168.75.129/24")

def packetsniffstart():

    #fetch global variables 
    global stopped
    global thread
    global subdomain

    #retrieve input from entry box
    subdomain = subdomaininput.get()
    #starts sniffing based on following conditions
    if (thread is None) or (not thread.is_alive()):
        stopped = False
        thread = threading.Thread(target=sniffnetwork)
        thread.start()

def packetsniffstop():
    global stopped
    #simply sets stopped to true, which program will check for
    stopped = True

def sniffnetwork():
    scapy.sniff(prn=getips, stop_filter=sniffingstop)

def sniffingstop(packet):
    global stopped
    return stopped


def getips(packet):

    #main get IP script for scapy
    global src_ip_dict
    global treev
    global subdomain


    print(packet.show())

    #check for IPv4 or IPv6 by checking for src & dst ip in packet
    source_IP = packet['IP'].src
    destination_IP = packet['IP'].dst
    if 'IP' in packet:
        
        source_IP = packet['IP'].src
        destination_IP = packet['IP'].dst
        #checks for subdomain in packet, trying to match user input

        if source_IP[0:len(subdomain)] == subdomain:

            #check for IP in source ip dictionary
            if source_IP not in src_ip_dict:
                time.sleep(1)
                src_ip_dict[source_IP].append(destination_IP) #appends destination IP to the end of source_IP in dictionary.

                packetrow = treev.insert('', index=tk.END, text=source_IP)
                treev.insert(packetrow, tk.END, text=destination_IP)
                treev.pack(fill=tk.X)



    else:
        if destination_IP not in src_ip_dict[Source_IP]:
            src_ip_dict[source_IP].append(destination_IP)#appends destination_IP to source dictionary.
            current_item = treev.focus()

            if (treev.item(current_item)['text'] == source_IP):
                treev.insert(current_item, tk.END, text=destination_IP)


### Introduction Screen ###










root.title("Register / Login")
root.geometry("400x300")

root.minsize(400, 300)
root.maxsize(400, 300)


intro_frame = tk.Frame(root, height='800', width='800')
intro_frame.pack()
intro_frame = tk.Frame(root)
intro_frame.place(relx=0.02, rely=0.02, relwidth=0.85, relheight=0.85)



##Button that registers
registerbutton = tk.Button(intro_frame, text="Register Now", font='Arial, 24', bg='#696969', command=registeruser, width='10')
registerbutton.place(relx='0.25', rely='0.25')

#button that logins
loginbutton = tk.Button(intro_frame, text="Login now", font='Arial, 24', bg='#696969', command=loginuserscreen, width='10')
loginbutton.place(relx='0.25', rely='0.5')


## welcome mesage


label = tk.Label(intro_frame, text="Welcome to the traffic analysis program.\n Please Register to begin.")
label.pack()

### register screen ####

registerscreen = Toplevel(root)
registerscreen.geometry("800x800")
registerscreen.title('Register Now')

registerscreen.wm_protocol("WM_DELETE_WINDOW", root.destroy)

registerscreen.minsize(400, 300)
registerscreen.maxsize(400, 300)

registerframe = tk.Frame(registerscreen,height='800', width='800')
registertext = tk.Label(registerframe, text="Welcome to the register page, \n please type in your username and password \n to create your account.").place(relx='0.5', rely='0.05', anchor='n')
registerframe.pack()

usernameregistry = tk.Entry(registerframe)
usernameregistry.place(relx='0.5', rely='0.35', anchor='n')
passwordregistry = tk.Entry(registerframe, show= '*')
passwordregistry.place(relx='0.5', rely='0.55', anchor='n')

registerlabel = tk.Label(registerframe, text="Username").place(relx='0.5', rely='0.25', anchor='n')
passwordlabel = tk.Label(registerframe, text="Password").place(relx='0.5', rely='0.45', anchor='n')

registerbutton = tk.Button(registerframe, text="Register Now",command=registeruserbutton).place(relx='0.5', rely='0.65', anchor='n')
registertoroot = tk.Button(registerframe, text="Back ", command=registertoroot).place(relx='0.8', rely='0.65', anchor='center')
registerscreen.withdraw()


### login screen ####

loginscreen = Toplevel(root)
loginscreen.geometry("400x300")
loginscreen.title('Login')

loginscreen.wm_protocol("WM_DELETE_WINDOW", root.destroy)

loginscreen.minsize(400, 300)
loginscreen.maxsize(400, 300)

#login success/failed messsage
welcomemessage=StringVar()


loginframe = tk.Frame(loginscreen, height='800', width='800')
logintext = tk.Label(loginframe, text="Welcome to the login page. \n To login, type in your username and password \n and hit login.").place(relx='0.5', rely='0.05', anchor='n')
loginframe.pack()


loginlabel = tk.Label(loginframe, text="Username")
loginlabel.place(relx='0.5', rely='0.25', anchor='n')
passwordlabel2 = tk.Label(loginframe, text="Password")
passwordlabel2.place(relx='0.5', rely='0.45', anchor='n')

usernamelogin = tk.Entry(loginframe, text="Username")
usernamelogin.place(relx='0.5', rely='0.35', anchor='n')
passwordlogin = tk.Entry(loginframe, show= '*', text="Password")
passwordlogin.place(relx='0.5', rely='0.55', anchor='n')

welcome = tk.Label(loginscreen, text="",textvariable=welcomemessage,bg="#1C2833",fg="white",font=("Arial",12,"bold"))
welcome.place(relx='0.15', rely='0.8')



loginbutton = tk.Button(loginframe, text="Login now", command=loginuser).place(relx='0.5', rely='0.75', anchor='center')
logintoroot = tk.Button(loginframe, text="Back ", command=logintoroot).place(relx='0.8', rely='0.65', anchor='center')
loginscreen.withdraw()
###  Main Menu Screen ###

winMenu = Toplevel(root)
winMenu.geometry("600x300")
winMenu.title('Main Menu')

winMenu.wm_protocol("WM_DELETE_WINDOW", root.destroy)

winMenu.minsize(600, 300)
winMenu.maxsize(600, 300)


    #Creation of Widgets in the window
winframe = tk.Frame(winMenu, height='800', width='800') ##, bg="#696969"
MenuText = tk.Label(winMenu, text="Welcome to the main menu, select a function to get started.")
MenuText.place(relx='0.5', rely='0.05', anchor='n')
winframe.pack()
winframe.place(relx='0.02', rely='0.02', relwidth='0.95', relheight='0.95')

module1 = tk.Button(winMenu, text="Ping tool",command=maintoping, width=10)
module1.place(relx='0.4', rely='0.5', anchor='e')
module2 = tk.Button(winMenu, text="Packet Sniffing", command=maintosniffer, width=10)
module2.place(relx='0.6', rely='0.5', anchor='e')
module3 = tk.Button(winMenu, text="ARP for devices", command=maintoarp, width = 10)
module3.place(relx='0.8', rely='0.5', anchor='e')
module4 = tk.Button(winMenu, text="Tutorial", command=maintotutorial, width = 10)
module4.place(relx='0.2', rely='0.9', anchor='e')


logout = tk.Button(winMenu,text="Logout", command=maintoroot, width = 5)
logout.place(relx='0.9', rely='0.9', anchor='e')

winMenu.withdraw()

#### Help/Tutorial Window ###
tutorialwindow = Toplevel(root)
tutorialwindow.geometry('800x600')
tutorialwindow.title('Tutorials, Help and Information')

tutorialwindow.wm_protocol("WM_DELETE_WINDOW", root.destroy)

tutorialintro = tk.Label(tutorialwindow, text="Welcome to the tutorial panel, here you will find FAQs and descriptions \n of the tools found on this application.")
tutorialintro.place(relx='0.5', rely='0.05', anchor='n')


pingertool= tk.Label(tutorialwindow, text="Pinger Tool", font='Arial, 20')
pingertool.place(relx='0.2', rely='0.25', anchor='n')

pingertool = tk.Label(tutorialwindow, text="The pinger tool will \n allow you to ping \n a URL or more \n importantly, an IP \n address that is on your system. \n You can use this to detect and \n in conjunction with \n the other tools, narrow \n down a particular machine \n and its status.", font='Arial, 10')
pingertool.place(relx='0.2', rely='0.4', anchor='n')

sniffertool = tk.Label(tutorialwindow, text="Sniffer Tool", font='Arial, 20')
sniffertool.place(relx='0.5', rely='0.25', anchor='n')

sniffertool = tk.Label(tutorialwindow, text="Sniffer is able to \n discover all devices \n on your network when \n they begin communicating \n also it will display \n who they are talking with \n in the network via IP.\n Please note the IP input \n should be based on your \n subnet class, meaning \n 192.168.75.128 for example \n would be \n192 as a C class, 192.168 as a B class \n and 192.168.75 as an A class.", font='Arial, 10')
sniffertool.place(relx='0.5', rely='0.4', anchor='n')

ARPtool = tk.Label(tutorialwindow, text="ARP Scan", font='Arial, 20')
ARPtool.place(relx='0.75', rely='0.25', anchor='n')

ARPtool = tk.Label(tutorialwindow, text="ARP Scan is capable \n of  scanning the network for \n active hosts,  helping catch \n unauthorized visitors and \n being able to inspect \n your network \n more easily.", font='Arial, 10')
ARPtool.place(relx='0.75', rely='0.4', anchor='n')

tutorialreturn = tk.Button(tutorialwindow, text="Back", command=tutorialtomain)
tutorialreturn.place(relx='0.05', rely ='0.9', anchor='n')
tutorialwindow.withdraw()
## Pinger Window - Used to ping systems on both private and public IPs, displays route information as well as other verbose information from the ping. ##
pingwindow = Toplevel(root)
pingwindow.geometry('400x400')
pingwindow.title('Pinger')

pingwindow.wm_protocol("WM_DELETE_WINDOW", root.destroy)

pinglabel1 = tk.Label(pingwindow, text="Enter URL/IP to test")
pinglabel1.place(relx='0.5', rely='0.1', anchor='n')
pinglabel2 = tk.Label(pingwindow, text="Outcome: ")
pinglabel2.place(relx='0.5', rely='0.2', anchor='n')


pingwindow.withdraw()
#label for res variable established earlier
reslabel = tk.Label(pingwindow, text="", textvariable=pingoutcome)
reslabel.place(relx='0.5', rely='0.3', anchor='n')

entryform = Entry(pingwindow)
entryform.place(relx='0.5', rely='0.8', anchor='n')

pingbutton = tk.Button(pingwindow, text="Go", command=get_ping)
pingbutton.place(relx='0.5', rely='0.9', anchor='n')

pingtomain = tk.Button(pingwindow, text="Back to main", command=pingtomain)
pingtomain.place(relx='0.8', rely='0.9', anchor='n')





#Packet Sniffer Window - Used to monitor activity in network between IPs

sniffer = Toplevel(root)
sniffer.geometry('400x500')

sniffer.wm_protocol("WM_DELETE_WINDOW", root.destroy)

sniffer.minsize(400, 500)
sniffer.maxsize(400, 500)

sniffer.title('Packet Sniffer')
sniffer.withdraw()
snifferlabel1 = tk.Label(sniffer, text='Welcome to the packet sniffer, \n please input the relevant IP address \n to begin monitoring your network. \n Please use this format depending on IP class \n A: 192.168.75 \n B: 192.168 \n C: 192')
snifferlabel1.place(relx='0.5', rely='0.44', anchor='n')

snifferlabel2 = tk.Label(sniffer, text='')




#treeview to show IP addresses from sniffer

treev = ttk.Treeview(sniffer)
treev.column('#0')
treev.place(relx='0.5', rely='0.22', anchor='center')





startsniff = tk.Button(sniffer, text='Begin Sniffing Network', command=packetsniffstart, width=30)
startsniff.place(relx='0.5', rely='0.75', anchor='n')

stopsniff = tk.Button(sniffer, text='Stop Sniffing Network', command=packetsniffstop, width=30)
stopsniff.place(relx='0.5', rely='0.80', anchor='n')

#user entry box for their subdomain
subdomaininput = tk.Entry(sniffer, width=30)
subdomaininput.place(relx='0.5', rely='0.7', anchor='n')

stopsniff = tk.Button(sniffer, text='Go back to menu', command=sniffertomain, width=20, height=2)
stopsniff.place(relx='0.5', rely='0.90', anchor='n')

## ARP Scanner Window

arpscanner = Toplevel(root)
arpscanner.geometry('400x400')
arpscanner.title('ARP Network Scanner')
arpscanner.wm_protocol("WM_DELETE_WINDOW", root.destroy)

arpscanner.minsize(400,400)
arpscanner.maxsize(400,400)

arptextscanner=tk.Text(arpscanner)
arptextscanner.pack()

arptextbutton=tk.Button(arpscanner, text='ARP Scan network', width='20', height='2',command=runarp)
arptextbutton.place(relx=0.5, rely=0.90, anchor='n')

arpexitbutton=tk.Button(arpscanner, text='Back', width='5', height='2', command=arptomain)
arpexitbutton.place(relx=0.2, rely=0.90, anchor='n')


arpscanner.withdraw()







root.mainloop() # End TKinter LOOP
























