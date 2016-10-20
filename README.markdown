ngx_upstream_jdomain
====================

An asynchronous domain name resolve module for nginx upstream

Installation:

	./configure --add-module=/path/to/this/directory
	make
	make install

Usage:

	upstream backend {                                                                              
		jdomain www.baidu.com; #port=80                                                             
		#jdomain www.baidu.com port=8080; #port=8080
	}                                                                                               
                                                                                                    
Jdomain: 

	* Syntax: jdomain <domain-name> [port=80] [max_ips=20] [interval=1] [retry_off] [no_fail] [backup_file] [temp_backup_dir] [backup_fsync]
	* Context:            upstream                                                                          
	* port:               Backend's listening port.                                                         
	* max_ips:            IP buffer size.
	* interval:           How many seconds to resolve domain name.
	* retry_off:          Do not retry if one IP fails.
	* no_fail:            Allow nginx to start up even if DNS resolve fails.
	* backup_file:        If DNS resolve fails at startup, load peers from this file.
	* temp_backup_dir:    Directory where temporary backup files are stored prior to being moved in place of the [backup_file].
	* backup_fsync:       Run fsync on temporary backup file before moving it.

See https://www.nginx.com/resources/wiki/modules/domain_resolve/ for details.

Authors
======

wdaike <wdaike@163.com>, Baidu Inc.

Victor Luchits <vluchits@gmail.com> Mail.Ru Group

Copyright & License
===================

This module is licenced under the BSD License.
Copyright (C) 2014-2014, by wdaike <wdaike@163.com>, Baidu Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

