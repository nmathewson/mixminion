#!/usr/bin/python2

import sys, re, tokenize, token


def countPyFile(fname):
    f = open(fname)
    codelines = {}
    lastline = 0
    IGNORE = (token.STRING, token.NEWLINE, token.INDENT, token.DEDENT)
    docstrlines = 0
    for toktp,tokstr,start,end,line in tokenize.generate_tokens(f.xreadlines().next):
        #print end[0], toktp, token.tok_name[toktp], repr(tokstr)
        lastline = end[0]
        if toktp in IGNORE or toktp >= token.N_TOKENS:
            continue
        
        codelines[end[0]] = toktp
    f.close()
    
    return len(codelines), lastline

c_comment_re = re.compile(r'/\*(?:[^*]+|[*]+[^/*])+\*+/')
cpp_comment_re = re.compile(r'//.*$')
def replacefn(m):
    return "\n"*(m.group(0).count("\n"))
blank_line_re = re.compile(r'^\s+$')

def countCFile(fname):
    f = open(fname)
    contents = f.read()
    f.close()

    contents = c_comment_re.sub(replacefn, contents)
    contents = cpp_comment_re.sub(replacefn, contents)
    contents = blank_line_re.sub("",contents)

    code,noncode = 0,0
    for line in contents.split("\n"):
        if line != "":
            code += 1
        else:
            noncode += 1

    return code,code+noncode

codeFiles = sys.argv[1:]
nonCodeFiles = []
if '--noncode' in codeFiles:
    idx = codeFiles.index("--noncode")
    nonCodeFiles = codeFiles[idx+1:]
    codeFiles = codeFiles[:idx]

print "========= Code files"
code,comments = 0,0
for f in codeFiles:
    if f.endswith(".py"):
        c,l = countPyFile(f)
    elif f.endswith(".c") or f.endswith(".h"):
        c,l = countCFile(f)
    code += c
    comments += (l-c)

    print "%4d %4d %2.2f %s" % (c, l-c, 100.0*c/l, f)

print "========= Non-code files"
noncode = 0
for f in nonCodeFiles:
    if f.endswith(".py"):
        c,l = countPyFile(f)
    elif f.endswith(".c") or f.endswith(".h"):
        c,l = countCFile(f)

    noncode += l
    print "%4d %4d %2.2f %s" % (c, l-c, 100.0*c/l, f)

print "TOTAL:"
total = code+noncode+comments
for item, lines in (("code", code),
                    ("tests", noncode),
                    ("docs", comments),
                    ("total", total)):
    print "%6.2f%% in %5s (%5d lines)" %((100.0*lines)/total, item, lines)


