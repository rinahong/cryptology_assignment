#!/usr/bin/python3.5

import sys, getopt

def main():
    runner()

def runner():
    ptextstr = '00101000'
    ptextLen = len(ptextstr)
    i = 1

    left = ptextstr[:ptextLen//2]
    right = ptextstr[ptextLen//2:]

    while(i <= 2):
        fnKey = fn(i, right, ptextstr)
        left = right
        right = str(desXOR(left, fnKey))
        i = i + 1

    result = left + right
    print(result)


def fn(index, right, ptextstr):
    ptextDecimal = int(right, 2)
    result = ((2 * index * 7) ** ptextDecimal) % 15
    return "{0:b}".format(result)


def desXOR(left, fnText):
    xor = int(left) ^ int(fnText)
    return str(xor)


if __name__ == "__main__":
    main ()
