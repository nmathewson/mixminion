# Implmentes the mixminion interface.
import os, sys
import re

# Give it a list of ommands and what should go in the std input
# it returns what appeared in the std output.
# PRIVATE: DO NOT CALL FROM OUTSIDE THIS MODULE!!!
def mm_command(cmd, in_str = None, show_stderr = 1):
    # c = cmd

    c = reduce(lambda x,y: x+" "+y, cmd)
    print c

    if show_stderr == 1:
        (sout,sin) = os.popen4(c)
    else:
        (sout,sin,serr) = os.popen3(c)

    if in_str != None:
        sout.write(in_str+'\n')
        sout.close()

    result = sin.read()
    return result

# provides a single use reply block
# If an error occus it return an empty list '[]'
def getSURB(addrs,login,passwd):
    rs = mm_command(['mixminion','generate-surb','--identity=\"%s\"'%login,'-t',addrs], passwd)
    surbPat = re.compile('-----BEGIN TYPE III REPLY BLOCK-----[^\-]*-----END TYPE III REPLY BLOCK-----',re.S)
    rs = surbPat.findall(rs)
    return rs

# routine to decode a received mixminion message
# If there is an error the empty string is returned.
def decode(msg,passwd):
    decPat = re.compile('-----BEGIN TYPE III ANONYMOUS MESSAGE-----\r?\nMessage-type: (plaintext|encrypted)(.*)-----END TYPE III ANONYMOUS MESSAGE-----\r?\n',re.S)
    mtc = decPat.search(msg)
    if mtc != None:
        f = open('__tempMM','w')
        f.write(mtc.group(0))
        f.close()
        rs = mm_command(['mixminion','decode','-i','__tempMM'], passwd, 0)
        # os.remove('__tempMM')
    rs.strip('\n')
    return rs+'\n'
    # Delete file!

# Simply sends a message
def send(msg,addrs,cmd):
    f = open('__msgMM','w')
    f.write(msg)
    f.close()

    rs = mm_command(['mixminion','send','-i','__msgMM','-t',addrs]+cmd, None)
    os.remove('__msgMM')
    return rs

# routine to send a message using mixminion.
def reply(msg,surb,cmd):
    f = open('__msgMM','w')
    f.write(msg)
    f.close()

    f = open('__surbMM','w')
    f.write(surb)
    f.close()

    rs = mm_command(['mixminion','send','-i','__msgMM','-R','__surbMM']+cmd, None)
    os.remove('__msgMM')
    os.remove('__surbMM')
    return rs
    # Delete files !!

# Old debugging information
if __name__ == '__main__':
    import getpass
    sb = getSURB('gd216@cl.cam.ac.uk',getpass.getpass())
    # reply('Hello world\nThis is my message\n',sb[0])

# print rs
