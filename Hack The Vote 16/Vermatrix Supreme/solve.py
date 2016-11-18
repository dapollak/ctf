import sys, random, time
from pwn import *

flag = "flag{1_sw34r_1F_p30Pl3_4cTu4lLy_TrY_Th1s}"

def printmat(matrix):
	for row in matrix:
		for value in row:
			print value,
		print ""
	print ""

def stringToMat(s):
	res1 = s.split('\n')
	res = []
	for l in res1:
		res += [l.split(' ')]

	return res


def pad(s):
	if len(s)%9 == 0:
		return s
	for i in xrange((9-(len(s)%9))):
		s.append(0)
	return s

def genBlockMatrix(s):
	outm = [[[7 for x in xrange(3)] for x in xrange(3)] for x in xrange(len(s)/9)]
	for matnum in xrange(0,len(s)/9):
		for y in xrange(0,3):
			for x in xrange(0,3):
				outm[matnum][y][x] = s[(matnum*9)+x+(y*3)]
	return outm

def genBlockMatrix_inv(outm):
	res = ['0']*len(outm)*9
	for matnum in xrange(len(outm)):
		for y in xrange(0,3):
			for x in xrange(0,3):
				res[(matnum*9)+x+(y*3)] = outm[matnum][y][x]
	return res


def fixmatrix(matrixa, matrixb):
	out = [[0 for x in xrange(3)] for x in xrange(3)]	
	for rn in xrange(3):
		for cn in xrange(3):
			# out(m, n) = (a(n, m)|b(m, n))&~(a(n, m)&b(m, n))
			# n-th bit == 1 if it is set in exactly one number.
			out[cn][rn] = (int(matrixa[rn][cn])|int(matrixb[cn][rn]))&~(int(matrixa[rn][cn])&int(matrixb[cn][rn]))
	return out

def fixmatrix_Inv(matrixa, matrixb):
	out = [[0 for x in xrange(3)] for x in xrange(3)]	
	for rn in xrange(3):
		for cn in xrange(3):
			# out(m, n) = (a(n, m)|b(m, n))&~(a(n, m)&b(m, n))
			# n-th bit == 1 if it is set in exactly one number.
			out[cn][rn] = (int(matrixa[rn][cn])|int(matrixb[rn][cn]))&~(int(matrixa[rn][cn])&int(matrixb[rn][cn]))
	return out

def find_IV(res, seed):
	seed_full = 'A'*9 + seed

	blocks = genBlockMatrix(pad([ord(c) for c in seed]))

	for i in xrange(len(seed)/9):
		res = fixmatrix_Inv(blocks[-1-i], res)

	res = fixmatrix([[0 for i in xrange(3)] for i in xrange(3)], res)
	return ','.join([','.join([str(c) for c in i]) for i in res])


def solve():
	p = remote('vermatrix.pwn.democrat', 4201)
	data = p.recv(2048, timeout=1)
	seed = data[6:data.find('\n')]
	matrix_s = data[data.find('\n'):][1:-1]
	matrix = stringToMat(matrix_s)
	iv = find_IV(matrix, seed)
	p.sendline(iv)
	return p.recv(2048, timeout=1)
