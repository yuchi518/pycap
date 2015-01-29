/*
 * Pcap extension for Python.
 * Copyright (C) 2015 Ubiquiti Networks (yuchi.chen@ubnt.com)
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

/**
 *  Install libpcap lib first and tested in version 1.6.2. (Download from http://www.tcpdump.org/#latest-release)
 *  Compile: gcc -I/usr/include/python3.4 -c pycap.c -o pycap.o
 *  Link: gcc -shared pycap.o -L/usr/local/lib -o pycap.so -lpcap
 *	Or install this module in system: sudo python3 setup.py install
 */


#include <Python.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "uthash.h"


struct PcapIf {
	char name[32];			// interface name large than 32bytes will ....
	PyObject *caller;
	PyObject *callback;	// python callback function
	pcap_t *source;
	int stop;
   UT_hash_handle hh;
};

static struct PcapIf *pcapIfs = NULL;
static PyObject *PcapError;

/*
 * Sample code to call system(...).
 */
static PyObject* pcap_system(PyObject *self, PyObject *args)
{
	const char *command;
	int sts;
	if (!PyArg_ParseTuple(args, "s", &command))
		return NULL;
	sts = system(command);
	if (sts < 0) {
		PyErr_SetString(PcapError, "System command failed");
		return NULL;
	}
   return PyLong_FromLong(sts);
	//return Py_None;
}

static inline void dispatch_to_py(struct PcapIf *IF, const struct pcap_pkthdr* pkthdr, const u_char * packet)
{
	PyObject *arglist;
	PyObject *result;
	PyObject *BUF;

	BUF = PyBytes_FromStringAndSize((void*)packet, (Py_ssize_t)pkthdr->caplen);

	arglist = Py_BuildValue("siiO", IF->name, (int)pkthdr->ts.tv_sec, (int)pkthdr->ts.tv_usec, BUF);
	result = PyObject_CallObject(IF->callback, arglist);
	//result = PyObject_CallMethod(IF->caller)
	Py_DECREF(arglist);
	Py_DECREF(BUF);
	if (result == NULL) return; /* Pass error back */
  	
  	Py_DECREF(result);
}

/* processPacket(): Callback function called by pcap_loop() everytime a packet */
/* arrives to the network card. This function prints the captured raw data in  */
/* hexadecimal.                                                                */
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char * packet) {
	
	struct PcapIf *IF;
	char *ifname = (char*)arg;

	HASH_FIND_STR(pcapIfs, ifname, IF);
	if (IF==NULL)
	{
		return;
	}
	dispatch_to_py(IF, pkthdr, packet);
} 

#define MAXBYTES2CAPTURE 2048
#define CALLBACK_MODE		1
static PyObject* pcap_capture(PyObject *self, PyObject *args)
{
	const char *tmpIfname;
	char ifname[32];
	pcap_t *source = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
   PyObject *tmpCB;
   struct PcapIf *IF;

   if (!PyArg_ParseTuple(args, "sO:capture", &tmpIfname, &tmpCB))
      return NULL;
   strncpy(ifname, tmpIfname, 32);
   
   if (!PyCallable_Check(tmpCB)) {
		PyErr_SetString(PyExc_TypeError, "parameter must be callable");
		return NULL;
	}

	HASH_FIND_STR(pcapIfs, ifname, IF);
	if (IF)
	{
		HASH_DEL(pcapIfs, IF);
		Py_XDECREF(IF->callback);
		free(IF);
	}

#if 1
   source = pcap_create(ifname, errbuf);
   if (source==NULL) {
      PyErr_SetString(PcapError, "Interface can't create.");
      return NULL;
   }

	if (pcap_set_snaplen(source, MAXBYTES2CAPTURE) < 0) {
		PyErr_SetString(PcapError, "Interface can't set_snaplen.");
		goto FAIL;
	}
	if (pcap_set_promisc(source, 1) < 0) {
		PyErr_SetString(PcapError, "Interface can't set_promisc.");
		goto FAIL;
	}
	if (pcap_set_timeout(source, 512) < 0) {
		PyErr_SetString(PcapError, "Interface can't set_timeout.");
		goto FAIL;
	}
	if (pcap_activate(source) < 0) {
		PyErr_SetString(PcapError, "Interface can't activate. (Are you miss 'sudo' ?)");
		goto FAIL;
	}
#else
	source = pcap_open_live(ifname, MAXBYTES2CAPTURE, 1, 512, errbuf);
	if (source==NULL) {
		PyErr_SetString(PcapError, "Interface can't create.");
      return NULL;
	}
#endif

	IF = (struct PcapIf*)malloc(sizeof(struct PcapIf));
	strncpy(IF->name, ifname, 32);
	Py_XINCREF(tmpCB);         /* Add a reference to new callback */
	IF->caller = self;
	IF->callback = tmpCB;       /* Remember new callback */
	IF->source = source;
	IF->stop = 0;
	HASH_ADD_STR(pcapIfs, name, IF);

	/* Boilerplate to return "None" */

#if CALLBACK_MODE
   /* Loop forever & call processPacket() for every received packet*/ 
	if (pcap_loop(source, -1, processPacket, (u_char *)ifname) == -1) {

	}
#else
	struct pcap_pkthdr *pkthdr;
	const u_char *packet;
	while(!IF->stop)
	switch (pcap_next_ex(source, &pkthdr, &packet))
	{
		case 1:
			// success
			dispatch_to_py(IF, pkthdr, packet);
			break;
		case 0:
			// timeout
			break;
		case -1:
			IF->stop = -1;
			// error
			break;
		case -2:
			IF->stop = -2;
			// EOR
			break;
	}
#endif

	// remove
	HASH_DEL(pcapIfs, IF);
	Py_XDECREF(IF->callback);
	free(IF);

FAIL:
	pcap_close(source);

   //return PyLong_FromLong(sts);
	return Py_None;
}

static PyObject* pcap_stop_capture(PyObject *self, PyObject *args)
{
	const char *tmpIfname;
	char ifname[32];
	struct PcapIf *IF;

	if (!PyArg_ParseTuple(args, "s", &tmpIfname))
		return NULL;
	strncpy(ifname, tmpIfname, 32);
	
	HASH_FIND_STR(pcapIfs, ifname, IF);
	if (IF)
	{
		#if CALLBACK_MODE
		// only notify should stop
		pcap_breakloop(IF->source);
		#else
		IF->stop = 1;
		#endif
		return Py_None;
	}
	else
	{
		PyErr_SetString(PcapError, "Interface not capture.");
		return NULL;
	}

}

/// init module code
static PyMethodDef Methods[] = {
    {"system",  pcap_system, METH_VARARGS, "Execute a shell command."},
    {"capture", pcap_capture, METH_VARARGS, "Start capture."},
    {"stop_capture", pcap_stop_capture, METH_VARARGS, "Stop capture."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef PyModule = {
   PyModuleDef_HEAD_INIT,
   "pycap",		/* name of module */
   NULL, 		/* module documentation, may be NULL */
   -1,			/* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   Methods
};


PyMODINIT_FUNC
PyInit_pycap(void)
{
    PyObject *m;

    m = PyModule_Create(&PyModule);
    if (m == NULL)
        return NULL;

    PcapError = PyErr_NewException("pycap.error", NULL, NULL);
    Py_INCREF(PcapError);
    PyModule_AddObject(m, "error", PcapError);
    return m;
}