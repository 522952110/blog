---
title: 安全开发
published: true
---

这是一份安全开源项目清单，收集了一些比较优秀的安全开源项目，以帮助甲方安全从业人员构建企业安全能力。

这些开源项目，每一个都在致力于解决一些安全问题。

项目收集的思路：

一个是关注互联网企业/团队的安全开源项目，经企业内部实践，这些最佳实践值得借鉴。一个是来自企业安全能力建设的需求，根据需求分类，如WAF、HIDS、Git监控等。

这个收集是一个长期的过程，我在GitHub创建了这个项目，专门用来收集一些优秀的甲方安全项目。还有很多很好的免费开源项目可供选择，下面列出的还只是其中很少的一部分，我将持续更新这个项目，欢迎Star。

## [](#header-2)GitHub项目地址：

https://github.com/Bypass007/Safety-Project-Collection

根据企业安全能力建设的需求，大致可以分为如下几种类型：

1、资产管理

BlueKing CMDB：一个面向资产及应用的企业级配置管理平台。



https://github.com/Tencent/bk-cmdb
OpsManage：一款代码部署、应用部署、计划任务、设备资产管理平台。



https://github.com/bongmu/OpsManage
Assets View：资产发现、网络拓扑管理系统。



https://github.com/Cryin/AssetsView
Ansible：一种集成 IT 系统的配置管理、应用部署、执行特定任务的开源平台。



https://www.ansible.com/
Saltstack：一个具备puppet与func功能为一身的集中化管理平台。



https://docs.saltstack.com/en/latest/
2、漏洞管理

insight：洞察-宜信集应用系统资产管理、漏洞全生命周期管理、安全知识库管理三位一体的平台。



https://github.com/creditease-sec/insight
xunfeng：一款适用于企业内网的漏洞快速应急，巡航扫描系统。



https://github.com/ysrc/xunfeng
SRCMS:企业应急响应与缺陷管理系统



https://github.com/martinzhou2015/SRCMS
laravel-src:基于 Laravel 的开源安全应急响应中心平台。



https://github.com/233sec/laravel-src
DefectDojo:一个安全程序和漏洞管理工具。



https://github.com/DefectDojo/django-DefectDojo
Fuxi-Scanner：一款开源的网络安全检测工具，适用于中小型企业对企业信息系统进行安全巡航检测。



https://github.com/jeffzh3ng/Fuxi-Scanner
SeMF：企业内网安全管理平台，包含资产管理，漏洞管理，账号管理，知识库管、安全扫描自动化功能模块，可用于企业内部的安全管理。



https://gitee.com/gy071089/SecurityManageFramwork
3、安全开发规范

rhizobia_J：JAVA安全SDK及编码规范。



https://github.com/momosecurity/rhizobia_J
rhizobia_P：PHP安全SDK及编码规范。



https://github.com/momosecurity/rhizobia_P
4、自动化代码审计

fortify：静态代码扫描工具。【破解即免费】。



http://www.fortify.net/
RIPS：用于PHP脚本漏洞的静态源代码分析器。



http://rips-scanner.sourceforge.net/
OpenStack Bandit：基于Python AST的静态分析器，用来查找Python代码中存在的通用安全问题的工具。



https://github.com/openstack/bandit/releases/
Cobra：一款源代码安全审计工具，支持检测多种开发语言源代码中的大部分显著的安全问题和漏洞。



https://github.com/WhaleShark-Team/cobra
banruo：基于的fotify的自动化代码审计系统。



https://github.com/yingshang/banruo
VCG：一种用于C++、C语言、VB、PHP、Java和PL/SQL的自动代码安全审查工具。



https://sourceforge.net/projects/visualcodegrepp/
Find Security Bugs：用于Java Web应用程序的安全审计。



https://find-sec-bugs.github.io/
Hades：静态代码脆弱性检测系统。



https://github.com/zsdlove/Hades
5、开源WAF

ngx_lua_waf：一个基于LUA-nginx的模块（openresty）的网络应用防火墙。



https://github.com/loveshell/ngx_lua_waf
OpenRASP：一款免费、开源的应用运行时自我保护产品。



https://rasp.baidu.com
ModSecurity：一个入侵侦测与防护引擎。



http://www.modsecurity.org/
锦衣盾：基于openresty(nginx+lua)开发的下一代web应用防火墙。



http://www.jxwaf.com
x-waf：适用于中小企业的云waf。



https://github.com/xsec-lab/x-waf
6、堡垒机

Jumpserver：全球首款完全开源的堡垒机，是符合4A的专业运维审计系统。



https://github.com/jumpserver/jumpserver
teleport：一款简单易用的开源堡垒机系统，支持RDP/SSH/SFTP/Telnet 协议的远程连接和审计管理。



https://tp4a.com/
CrazyEye：基于Python的开发的一款简单易用的IT审计堡垒机。



https://github.com/triaquae/CrazyEye
gateone：一款使用HTML5技术编写的网页版SSH终端模拟器。



https://github.com/liftoff/GateOne
JXOTP：一款企业SSH登陆双因素认证系统。



https://github.com/jx-sec/jxotp
麒麟堡垒机：开源版只支持一部分功能，剩下的功能需要购买。



https://www.tosec.com.cn/
7、HIDS

OSSEC：一款开源的IDS检测系统，包括了日志分析、完整性检查、rook-kit检测，基于时间的警报和主动响应。



https://www.ossec.net
Wazuh：一个免费的，开源的企业级安全监控解决方案，用于威胁检测，完整性监控，事件响应和合规性。



http://wazuh.com
Suricata：一个免费的开源，成熟，快速和强大的网络威胁检测引擎。



https://suricata-ids.org
Snort：网络入侵检测和预防系统。



https://www.snort.org
Osquery:一个SQL驱动操作系统检测和分析工具。



https://osquery.io/
Samhain Labs：用于集中式主机完整性监控的全面开源解决方案。



https://www.la-samhna.de/
Firestorm：一种极高性能的网络入侵检测系统（NIDS）。



http://www.scaramanga.co.uk/firestorm/
MozDef：Mozilla防御平台,一套实时集成化平台，能够实现监控、反应、协作并改进相关保护功能。



https://github.com/mozilla/MozDef
驭龙HIDS：开源的主机入侵检测系统。



https://github.com/ysrc/yulong-hids
AgentSmith-HIDS：轻量级的HIDS系统，低性能损失，使用LKM技术的HIDS工具。



https://github.com/DianrongSecurity/AgentSmith-HIDS
Sobek-Hids：一个基于python的HostIDS系统。



http://www.codeforge.cn/article/331327
Security Onion:免费开源网络安全监控系统。



https://securityonion.net/
OpenWIPS-ng：一款开源的模块化无线IPS（Intrusion Prevention System，入侵防御系统）。



http://openwips-ng.org/
Moloch: 网络流量收集与分析。



https://www.dictionary.com/browse/moloch
8、网络流量分析

Zeek：一个功能强大的网络分析框架。



https://www.zeek.org
Kismet：一种无线网络和设备检测器，嗅探器，驱动工具和WIDS（无线入侵检测）框架。



https://www.kismetwireless.net/
9、SIEM/SOC

OSSIM：开源安全信息管理系统，它是一个开源安全信息和事件的管理系统，集成了一系列的能够帮助管理员更好的进行计算机安全，入侵检测和预防的工具。



https://www.alienvault.com/products/ossim
Apache Metron：一种网络安全应用程序框架，使组织能够检测网络异常并使组织能够快速响应已识别的异常情况。



https://github.com/apache/metron
SIEMonster：以很小的成本监控整个网络。



https://siemonster.com/
w3a_SOC：Web日志审计与网络监控集合一身的平台。



https://github.com/smarttang/w3a_SOC
OpenSOC：致力于提供一个可扩展和可扩展的高级安全分析工具。



http://opensoc.github.io/
Prelude：一个结合了其他各种开源工具的SIEM框架。



https://www.prelude-siem.org/
MozDef：Mozilla防御平台,一套实时集成化平台，能够实现监控、反应、协作并改进相关保护功能。



https://github.com/jeffbryner/MozDef
10、企业云盘

KodExplorer：可道云，是基于Web技术的私有云在线文档管理解决方案。



https://kodcloud.com/
Seafile：一款开源的企业云盘，注重可靠性和性能。



https://www.seafile.com/home/
NextCloud:一款开源网络硬盘系统。



https://nextcloud.com/
owncloud：一个基于Linux的开源云项目。



https://owncloud.com/products/
iBarn：基于PHP的开源网盘。



http://www.godeye.org/code/ibarn
Cloudreve：以最低的成本快速搭建公私兼备的网盘系统。



http://cloudreve.org/
Filebrowser：一个基于GO的轻量级文件管理系统。



https://github.com/filebrowser/filebrowser/releases/latest
FileRun：一款强大的多功能网盘和文件管理器。



https://filerun.com/
kiftd：一款专门面向个人、团队和小型组织的私有网盘系统。



https://github.com/KOHGYLW/kiftd
11、钓鱼网站系统

HFish:一款基于 Golang 开发的跨平台多功能主动诱导型蜜罐框架系统。



https://github.com/hacklcx/HFish
mail_fishing：基于thinkphp写的一个内部钓鱼网站系统。



https://github.com/SecurityPaper/mail_fishing
Gophish：开源钓鱼工具包。



https://github.com/gophish/gophish
BLACKEYE：开源钓鱼工具包。



https://github.com/thelinuxchoice/blackeye
phishing:甲方网络钓鱼的安全实践。



https://github.com/p1r06u3/phishing
Phishing Frenzy:开源的钓鱼测试工具。



https://www.phishingfrenzy.com/
King Phisher:一款专业的钓鱼活动工具包。



https://github.com/rsmusllp/king-phisher/
12、蜜罐技术

T-Pot：多蜜罐平台，可视化分析。



https://github.com/dtag-dev-sec/tpotce/
HFish：一种基于Golang开发的跨平台多功能主动诱导型蜜罐框架系统。



https://github.com/hacklcx/HFish
opencanary_web：蜜罐的网络管理平台。



https://github.com/p1r06u3/opencanary_web
Honeyd：一个小型守护进程，可以在网络上创建虚拟主机。



http://www.honeyd.org/
mhn：现代蜜罐网络。



http://threatstream.github.io/mhn/
Glastopf：Python Web应用程序蜜罐。



https://github.com/mushorg/glastopf
Cowrie：一种中等交互式SSH和Telnet蜜罐，用于记录暴力攻击和攻击者执行的shell交互。



https://github.com/cowrie/cowrie
Kippo：一个中等交互式SSH蜜罐，用于记录暴力攻击，最重要的是，攻击者执行的整个shell交互。



https://github.com/desaster/kippo
Dionaea：一个低交互的蜜罐，能够模拟FTP/HTTP/MSSQL/MYSQL/SMB等服务。



https://github.com/DinoTools/dionaea
Conpot：一个ICS蜜罐，其目标是收集有关针对工业控制系统的敌人的动机和方法的情报。



https://github.com/mushorg/conpot
Wordpot：一个Wordpress蜜罐，可以检测用于指纹wordpress安装的插件，主题，timthumb和其他常用文件的探针。



https://github.com/gbrindisi/wordpot
elastichoney：一个简单的Elasticsearch蜜罐。



https://github.com/jordan-wright/elastichoney
beeswarm：一个蜜罐项目，为蜜罐的配置、部署和管理提供了便利。



https://github.com/honeynet/beeswarm
Shockpot：一个Web应用程序蜜罐，旨在找到试图利用Bash远程代码漏洞的攻击者，CVE-2014-6271。



https://github.com/threatstream/shockpot
13、安全运维

Scout：URL 监控系统。



https://github.com/HandsomeOne/Scout
OpenDnsdb：开源的基于Python语言的DNS管理系统 。



https://github.com/qunarcorp/open_dnsdb
cuckoo：一个自动化的动态恶意软件分析系统。



https://github.com/cuckoosandbox/cuckoo
theZoo：一个恶意软件分析项目。



https://github.com/ytisf/theZoo
OpenDLP：一个免费的，开源的，基于代理和无代理的，集中管理，可大规模分发的数据丢失防护工具。



https://code.google.com/archive/p/opendlp/
14、GitHub监控

GSIL：GitHub敏感信息泄漏工具。



https://github.com/FeeiCN/GSIL
Hawkeye：监控github代码库，及时发现员工托管公司代码到GitHub行为并预警，降低代码泄露风险。



https://github.com/0xbug/Hawkeye
x-patrol：GitHub的泄露扫描系统—MiSecurity。



https://github.com/MiSecurity/x-patrol
Github-Monitor：用于监控Github代码仓库的系统。



https://github.com/VKSRC/Github-Monitor
gshark：轻松有效地扫描Github中的敏感信息。



https://github.com/neal1991/gshark
GitGuardian：实时扫描GitHub活动的解决方案。



https://www.gitguardian.com/
code6：码小六 - GitHub 代码泄露监控系统。



https://github.com/4x99/code6
15、风控系统

TH-Nebula：星云风控系统是一套互联网风控分析和检测平台。



https://github.com/threathunterX/nebula
Liudao：六道”实时业务风控系统。



https://github.com/ysrc/Liudao
陌陌风控系统：静态规则引擎，零基础简易便捷的配置多种复杂规则，实时高效管控用户异常行为。



https://github.com/momosecurity/aswan
Drools：基于java的功能强大的开源规则引擎。

https://www.drools.or
