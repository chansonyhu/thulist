var wall_proxy = "SOCKS5 127.0.0.1:1080;";
var nowall_proxy = "DIRECT;";
var direct = "DIRECT;";
var ip_proxy = "DIRECT;";

/*
 * Copyright (C) 2014 breakwa11
 * https://github.com/breakwa11/gfw_whitelist
 */

var cnIpRange = [
{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{0xd34411:1,0xd3447e:1,0xca2663:1,0xca703a:1,0xca7039:1,0xca7038:1,0xca7030:8,0xca702f:1,0xca702d:1,0xca702c:1,0xca702b:1,0xca7027:1,0xca7023:1,0xca7003:1,0xb7ad00:256,0xb7ac00:256,0x76e500:32,0x6a7884:4,0x650600:256,0x650500:256,0x3b4200:256,0xa66f00:256}
];
var cnIp16Range = {
0x1a9e2:1,0x1db94:1,0x32899:1,0x329c0:1,0x34d10:1,0x34d11:1
};

var subnetIpRangeList = [
0,1,
167772160,184549376,	//10.0.0.0/8
2886729728,2887778304,	//172.16.0.0/12
3232235520,3232301056,	//192.168.0.0/16
2130706432,2130706688	//127.0.0.0/24
];

var hasOwnProperty = Object.hasOwnProperty;

function check_ipv4(host) {
	var re_ipv4 = /^\d+\.\d+\.\d+\.\d+$/g;
	if (re_ipv4.test(host)) {
		return true;
	}
}
function convertAddress(ipchars) {
	var bytes = ipchars.split('.');
	var result = (bytes[0] << 24) |
	(bytes[1] << 16) |
	(bytes[2] << 8) |
	(bytes[3]);
	return result >>> 0;
}
function getProxyFromDirectIP(strIp) {
	var intIp = convertAddress(strIp);
	if ( isInSubnetRange(subnetIpRangeList, intIp) ) {
		return direct;
	}
	return ip_proxy;
}
function isInSingleRange(ipRange, intIp) {
	if ( hasOwnProperty.call(cnIp16Range, intIp >>> 6) ) {
		for ( var range = 1; range < 64; range*=4 ) {
			var master = intIp & ~(range-1);
			if ( hasOwnProperty.call(ipRange, master) )
				return intIp - master < ipRange[master];
		}
	} else {
		for ( var range = 64; range <= 1024; range*=4 ) {
			var master = intIp & ~(range-1);
			if ( hasOwnProperty.call(ipRange, master) )
				return intIp - master < ipRange[master];
		}
	}
}
function isInSubnetRange(ipRange, intIp) {
	for ( var i = 0; i < 10; i += 2 ) {
		if ( ipRange[i] <= intIp && intIp < ipRange[i+1] )
			return true;
	}
}
function getProxyFromIP(strIp) {
	var intIp = convertAddress(strIp);
	if ( isInSubnetRange(subnetIpRangeList, intIp) ) {
		return direct;
	}
	var index = (intIp >>> 24) & 0xff;
	if ( isInSingleRange(cnIpRange[index], intIp >>> 8) ) {
		return nowall_proxy;
	}
	return wall_proxy;
}
function FindProxyForURL(url, host) {
	if ( isPlainHostName(host) === true ) {
		return direct;
	}
	if ( check_ipv4(host) === true ) {
		return getProxyFromDirectIP(host);
	}

	var strIp = dnsResolve(host);
	if (!strIp) {
		return wall_proxy;
	}
	
	return getProxyFromIP(strIp);
}

