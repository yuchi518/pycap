#!/usr/bin/env python3

# Ethernet packets capturer.
# Copyright (C) 2015 Ubiquiti Networks (yuchi.chen@ubnt.com)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# 
# Run: sudo ./cap.py
#

import os, sys,time
import pycap
import threading
import struct

class Capturer(threading.Thread):
	def __init__(self, ifname, filename=None):
		threading.Thread.__init__(self)
		self.ifname = ifname
		self.cntOfPkts = 0
		self.capturing = False
		self.filename = filename
		self.fo = None
	
	def run(self):
		self.capturing = True
		fo = None
		if self.filename!=None:
			fo = open(self.filename, "wb")
			self.fo = fo

		pycap.capture(self.ifname, self.capture)

		if fo!=None:
			self.fo = None
			fo.close()

		self.capturing = False

	def capture(self, ifname, sec, usec, pkt_arr):
		self.cntOfPkts = self.cntOfPkts + 1
		print("[%s]GOT (%d sec, %d usec)" % (ifname, sec, usec))
		if self.fo!=None:
			self.fo.write(struct.pack("i", sec))
			self.fo.write(struct.pack("i", usec))
			self.fo.write(struct.pack("i", len(pkt_arr)))
			self.fo.write(pkt_arr)			

		#if self.cntOfPkts>10:
		#	pycap.stop_capture(self.ifname)

	def stopCapture(self):
		if not self.capturing: return
		#print("Try to stop %s" % self.ifname)
		pycap.stop_capture(self.ifname)

'''
COUNT = 0
def got_pkt(ifname, sec, usec, pkt_arr):
	global COUNT
	COUNT = COUNT+1
	print("[%s]GOT (%d sec, %d usec, %s)" % (ifname, sec, usec, pkt_arr))

	if COUNT>10:
		pycap.stop_capture("eth0")
'''

capturers = []
if len(sys.argv) > 1:
	for i in range(1, len(sys.argv)):
		cap = Capturer(sys.argv[i], filename=sys.argv[i]+".raw")
		cap.start()
		capturers.append(cap)

if len(capturers)>0:
	#print("Start")
	while(True):
		cmd = input("?")
		if cmd=="stop":
			for cap in capturers:
				cap.stopCapture()
				cap.join()
			break
'''
	time.sleep(1)		# wait thread running
	while(True):
		stopCnt = 0
		for cap in capturers:
			if cap.cntOfPkts>10:
				cap.stopCapture()
				cap.join()
			if not cap.capturing: stopCnt = stopCnt+1

		if stopCnt >= len(capturers): break
		time.sleep(1)
'''
	#print("Stop");





