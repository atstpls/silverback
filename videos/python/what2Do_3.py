#! /usr/bin/env python3
# -*- coding: utf-8 -*-
import sys,random
from colorama import init
init()

def pick():
    case={
        0:'do nothing',
        1:'go for long run',
        2:'do a metcon',
        3:'read a book',
        4:'take a nap',
        5:'cut the grass',
        6:'play a game'
    }

    randNum = random.randint(0,6)
    return case.get(randNum,"Error")

header = '''
\033[92m        .----------------------------------.
\033[92m        |  .----------------------------.  |
\033[92m        |  |\033[94m                            \033[92m|  |
\033[92m        |  |\033[94m              ._ o o        \033[92m|  |
\033[92m        |  |\033[94m              \_`-)|_       \033[92m|  |
\033[92m        |  |\033[94m           ,""       \      \033[92m|  |
\033[92m        |  |\033[94m         ,"  ## |   ಠ ಠ.    \033[92m|  |
\033[92m        |  |\033[94m       ," ##   ,-\__    `.  \033[92m|  |
\033[92m        |  |\033[94m     ,"       /     `--._;) \033[92m|  |
\033[92m        |  |\033[94m   ,"     ## /              \033[92m|  |
\033[92m        |  |\033[94m ,"   ##    /               \033[92m|  |
\033[92m        |  |\033[94m                            \033[92m|  |
\033[92m        |  '----------------------------'  |
\033[92m        '----------------------------------'
'''

print(header)

thing = pick()

print("\033[96m\tGiraffe says you should " + thing)
print("\n")

info = sys.version_info
vers = str(info.major) + "." + str(info.minor) + "." + str(info.micro)

print("\033[91m\tProgram: " + "\033[0m" + sys.executable)
print("\033[91m\tVersion: " + "\033[0m" + vers)
print("\n")

input("\033[90m\tPress any key to exit\n\n")
