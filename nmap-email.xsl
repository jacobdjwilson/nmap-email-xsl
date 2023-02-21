<?xml version="1.0"?>
<!-- =========================================================================
            nmap-email.xsl stylesheet version 1.0
            A simple fork of nmap.xsl meant for email clients
            Copyright (c) 2023 Jacob Wilson <jacobdjwilson@gmail.com>
            All rights reserved.
            Creative Commons BY-SA

==============================================================================
            nmap.xsl stylesheet version 0.9c
            last change: 2010-12-28
            Benjamin Erb, http://www.benjamin-erb.de
==============================================================================
    Copyright (c) 2004-2006 Benjamin Erb
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
    3. The name of the author may not be used to endorse or promote products
       derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
    IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
    NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
    THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
========================================================================== -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format">
<xsl:output  method="html" indent="yes" encoding="UTF-8"/>
<xsl:variable name="start"><xsl:value-of select="/nmaprun/@startstr" /></xsl:variable>
<xsl:variable name="end"><xsl:value-of select="/nmaprun/runstats/finished/@timestr" /> </xsl:variable>
<xsl:variable name="totaltime"><xsl:value-of select="/nmaprun/runstats/finished/@time -/nmaprun/@start" /></xsl:variable>
<xsl:key name="portstatus" match="@state" use="."/>
<xsl:template match="/">
	<xsl:apply-templates/>
</xsl:template>
<xsl:template match="/nmaprun">
  <a name="top" />
    <h1 style="color:#fff;background-color:#000842;text-align:left;font-size:2em;width:100%;font-family:Arial;">Nmap Scan Report - Scanned at <xsl:value-of select="$start" /></h1>
    <h3 style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><a href="#scansummary">Scan Summary</a></h3>
            <xsl:if test="prescript/script/@id">
        <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
          <a href="#prescript">Pre-Scan Script Output</a>
        </li>
      </xsl:if>
      <xsl:for-each select="host">
        <xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>
        <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
          <xsl:element name="a">
            <xsl:attribute name="href">#host_<xsl:value-of select="translate(address/@addr, '.', '_') " /></xsl:attribute>
            <xsl:attribute name="class">
              <xsl:choose>
                <xsl:when test="status/@state = 'up'">up</xsl:when>
                <xsl:otherwise>down</xsl:otherwise>
              </xsl:choose>
            </xsl:attribute>
            <xsl:variable name="var_address" select="address/@addr" />
            <xsl:if test="count(hostnames/hostname) > 0">
              <xsl:for-each select="hostnames">
                <xsl:choose>
                  <xsl:when test="hostname/@type='user'">
                    <xsl:value-of select="hostname/@name"/>
                    (<xsl:value-of select="$var_address"/>)
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:for-each select="hostname/@name[hostname/@type='PTR']"/>
                    <xsl:value-of select="hostname/@name"/> (<xsl:value-of select="$var_address"/>)
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:for-each>
            </xsl:if>
            <xsl:if test="count(hostnames/hostname) = 0">
              <xsl:value-of select="address/@addr"/>
            </xsl:if>
          </xsl:element>
        </li>
      </xsl:for-each>
      <xsl:if test="postscript/script/@id">
        <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:text></xsl:text><a href="#postscript">Post-Scan Script Output</a></li>
      </xsl:if>
    <xsl:element name="a">
      <xsl:attribute name="name">scansummary</xsl:attribute>
    </xsl:element>
    <h2 style="color:#000; margin:3px 0 3px 0;font-size:16px;line-height:24px;font-family:Arial;">Scan Summary</h2>
    <p  style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
      Nmap <xsl:value-of select="@version" /> was initiated at <xsl:value-of select="$start" /> with these arguments:<br/>
      <i><xsl:value-of select="@args" /></i><br/>
    </p>
    <p  style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
    Verbosity: <xsl:value-of select="verbose/@level" />; Debug level <xsl:value-of select="debugging/@level" />
    </p>
    <p  style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
    <xsl:value-of select="/nmaprun/runstats/finished/@summary" />
    </p>
    <xsl:apply-templates select="prescript"/>
    <xsl:apply-templates select="host">
      <xsl:sort select="substring ( address/@addr, 1, string-length ( substring-before ( address/@addr, '.' ) ) )* (256*256*256) + substring ( substring-after ( address/@addr, '.' ), 1, string-length ( substring-before ( substring-after ( address/@addr, '.' ), '.' ) ) )* (256*256) + substring ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), 1, string-length ( substring-before ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ) ) ) * 256 + substring ( substring-after ( substring-after ( substring-after ( address/@addr, '.' ), '.' ), '.' ), 1 )" order="ascending" data-type="number"/>
    </xsl:apply-templates>
    <a href="#top"><h3 style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Go to top</h3></a>
    <xsl:apply-templates select="postscript"/>
</xsl:template>
<!-- ............................................................ -->
<!-- host -->
<!-- ............................................................ -->
<xsl:template match="host">
  <xsl:variable name="var_address" select="address/@addr" />
  <xsl:element name="a">
    <xsl:attribute name="name">host_<xsl:value-of select="translate(address/@addr, '.', '_') " /></xsl:attribute>
  </xsl:element>
  <xsl:choose>
    <xsl:when test="status/@state = 'up'">
      <h2 style="color:#fff; background-color:#000842; margin:1px 0 1px 0;font-size:24px;line-height:36px;font-family:Arial;" class="up"><xsl:value-of select="address/@addr"/>
      <xsl:if test="count(hostnames/hostname) > 0">
        <xsl:for-each select="hostnames/hostname">
          <xsl:sort select="@name" order="ascending" data-type="text"/>
            <xsl:text> / </xsl:text><xsl:value-of select="@name"/>
        </xsl:for-each>
      </xsl:if>
      <span> (online)</span>
      </h2>
    </xsl:when>
    <xsl:otherwise>
      <h2 style="color:#fff; background-color:#000842; margin:1px 0 1px 0;font-size:24px;line-height:36px;font-family:Arial;" class="down"><xsl:value-of select="address/@addr"/>
      <xsl:if test="count(hostnames/hostname) > 0">
        <xsl:for-each select="hostnames/hostname">
          <xsl:sort select="@name" order="ascending" data-type="text"/>
            <xsl:text> / </xsl:text><xsl:value-of select="@name"/>
        </xsl:for-each>
      </xsl:if>
      <span> (offline)</span></h2>
    </xsl:otherwise>
  </xsl:choose>
  <xsl:element name="p">
    <xsl:attribute name="id">hostblock_<xsl:value-of select="$var_address"/></xsl:attribute>
    <xsl:choose>
      <xsl:when test="status/@state = 'up'">
        <xsl:attribute name="class">unhidden</xsl:attribute>
      </xsl:when>
      <xsl:otherwise>
      </xsl:otherwise>
    </xsl:choose>
  <xsl:if test="count(address) > 0">
    <h3 style="color:#fff; background-color:#003366; margin:2px 0 2px 0;font-size:16px;line-height:24px;font-family:Arial;">Address</h3>
        <xsl:for-each select="address">
          <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@addr"/>
            <xsl:if test="@vendor">
              <xsl:text> - </xsl:text>
                <xsl:value-of select="@vendor"/>
              <xsl:text> </xsl:text>
            </xsl:if>
            (<xsl:value-of select="@addrtype"/>)
          </li>
        </xsl:for-each>
  </xsl:if>
  <xsl:apply-templates/>
  <xsl:element name="p">
    <xsl:attribute name="id">metrics_<xsl:value-of select="$var_address"/></xsl:attribute>
    <table cellspacing="0.5">
      <tr style="color:#000;background-color:#ddd;text-align:left;padding:0;vertical-align:top;" class="head">
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;font-weight: bold;line-height:16px;font-family:Arial;">Metric</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;font-weight: bold;line-height:16px;font-family:Arial;">Value</p></td>
      </tr>
      <tr>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Ping Results</p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="status/@reason"/>
          <xsl:if test="status/@reasonsrc">
            <xsl:text> from </xsl:text>
            <xsl:value-of select="status/@reasonsrc"/>
          </xsl:if>
        </p></td>
      </tr>
    <xsl:if test="uptime/@seconds != ''">
      <tr>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">System Uptime</p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="uptime/@seconds" /> seconds  (last reboot: <xsl:value-of select="uptime/@lastboot" />)
        </p></td>
      </tr>
    </xsl:if>
    <xsl:if test="distance/@value != ''">
      <tr>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Network Distance</p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="distance/@value" /> hops</p></td>
      </tr>
    </xsl:if>
    <xsl:if test="tcpsequence/@index != ''">
      <tr>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">TCP Sequence Prediction</p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Difficulty=<xsl:value-of select="tcpsequence/@index" /> (<xsl:value-of select="tcpsequence/@difficulty" />)</p></td>
      </tr>
    </xsl:if>
    <xsl:if test="ipidsequence/@class != ''">
      <tr>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">IP ID Sequence Generation</p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="ipidsequence/@class" /></p></td>
      </tr>
    </xsl:if>
      </table>
    </xsl:element>
  </xsl:element>
</xsl:template>
<!-- ............................................................ -->
<!-- hostnames -->
<!-- ............................................................ -->
<xsl:template match="hostnames">
  <xsl:if test="hostname/@name != ''"><h3 style="color:#fff; background-color:#003366; margin:2px 0 2px 0;font-size:16px;line-height:24px;font-family:Arial;">Hostnames</h3><xsl:apply-templates/></xsl:if>
</xsl:template>
<!-- ............................................................ -->
<!-- hostname -->
<!-- ............................................................ -->
<xsl:template match="hostname">
  <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@name"/> (<xsl:value-of select="@type"/>)</li>
</xsl:template>
<!-- ............................................................ -->
<!-- ports -->
<!-- ............................................................ -->
<xsl:template match="ports">
  <xsl:variable name="var_address" select="../address/@addr" />
  <h3 style="color:#fff; background-color:#003366; margin:2px 0 2px 0;font-size:16px;line-height:24px;font-family:Arial;">Ports</h3>
  <xsl:for-each select="extraports">
    <xsl:if test="@count > 0">
      <p  style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">The <xsl:value-of select="@count" /> ports scanned but not shown below are in state: <b><xsl:value-of select="@state" /></b></p>
    </xsl:if>
    <ul style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
      <xsl:for-each select="extrareasons">
        <xsl:if test="@count > 0">
          <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><p  style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@count" /> ports replied with: <b><xsl:value-of select="@reason" /></b></p></li>
        </xsl:if>
      </xsl:for-each>
    </ul>
  </xsl:for-each>
  <xsl:if test="count(port) > 0">
    <xsl:for-each select="port/state/@state[generate-id()=generate-id(key('portstatus',.))]" />
    <xsl:variable name="closed_count" select="count(port/state[@state='closed'])" />
    <xsl:variable name="filtered_count" select="count(port/state[@state='filtered'])" />
    <xsl:element name="table">
      <xsl:attribute name="id">porttable_<xsl:value-of select="$var_address"/></xsl:attribute>
      <xsl:attribute name="cellspacing">1</xsl:attribute>
    <tr style="color:#000;background-color:#ddd;text-align:left;padding:0;vertical-align:top;" class="head">
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;font-weight: bold;">Port</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;font-weight: bold;">State</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;font-weight: bold;">Service</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;font-weight: bold;">Reason</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;font-weight: bold;">Product</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;font-weight: bold;">Version</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;font-weight: bold;">Info</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;font-weight: bold;">Info</p></td>
      </tr>
      <xsl:apply-templates/>
    </xsl:element>
  </xsl:if>
</xsl:template>
<!-- ............................................................ -->
<!-- port -->
<!-- ............................................................ -->
<xsl:template match="port">
  <xsl:choose>
    <xsl:when test="state/@state = 'open'">
      <tr class="open">
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@portid" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@protocol" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="state/@state" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></p></td>
	<td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="state/@reason"/>
          <xsl:if test="state/@reason_ip">
            <xsl:text> from </xsl:text>
            <xsl:value-of select="state/@reason_ip"/>
          </xsl:if>
        </p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></p></td>
      </tr>
      <xsl:for-each select="script">
        <tr class="script">
          <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"></p></td>
          <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text></p></td>
          <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
            <pre><xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text></pre>
          </p></td>
        </tr>
      </xsl:for-each>
    </xsl:when>
    <xsl:when test="state/@state = 'filtered'">
      <tr class="filtered">
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@portid" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@protocol" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="state/@state" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="state/@reason"/>
          <xsl:if test="state/@reason_ip">
            <xsl:text> from </xsl:text>
            <xsl:value-of select="state/@reason_ip"/>
          </xsl:if>
        </p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></p></td>
      </tr>
    </xsl:when>
    <xsl:when test="state/@state = 'closed'">
      <tr class="closed">
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@portid" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@protocol" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="state/@state" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="state/@reason"/>
          <xsl:if test="state/@reason_ip">
            <xsl:text> from </xsl:text>
            <xsl:value-of select="state/@reason_ip"/>
          </xsl:if>
        </p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></p></td>
      </tr>
    </xsl:when>
    <xsl:otherwise>
      <tr>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@portid" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@protocol" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="state/@state" /></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@name" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="state/@reason"/>
          <xsl:if test="state/@reason_ip">
            <xsl:text> from </xsl:text>
            <xsl:value-of select="state/@reason_ip"/>
          </xsl:if>
	</p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@product" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@version" /><xsl:text>&#xA0;</xsl:text></p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="service/@extrainfo" /><xsl:text>&#xA0;</xsl:text></p></td>
      </tr>
    </xsl:otherwise>
  </xsl:choose>
</xsl:template>
<!-- ............................................................ -->
<!-- os -->
<!-- ............................................................ -->
<xsl:template match="os">
  <h3 style="color:#fff; background-color:#003366; margin:2px 0 2px 0;font-size:16px;font-weight: bold;line-height:24px;font-family:Arial;">Remote Operating System Detection</h3>
  <xsl:if test="count(osmatch) = 0"><p  style="margin:1px 0 1px 0;font-size:12px;font-weight: bold;line-height:16px;font-family:Arial;">Unable to identify operating system.</p></xsl:if>
    <xsl:for-each select="portused">
      <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Used port: <b><xsl:value-of select="@portid" />/<xsl:value-of select="@proto" /> </b> (<b><xsl:value-of select="@state" /></b>)  </li>
    </xsl:for-each>
    <xsl:for-each select="osmatch">
      <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">OS match: <b><xsl:value-of select="@name" /> </b> (<b><xsl:value-of select="@accuracy" />%</b>)</li>
    </xsl:for-each>
  <xsl:apply-templates select="osfingerprint"/>
</xsl:template>
<!-- ............................................................ -->
<!-- osfingerprint -->
<!-- ............................................................ -->
<xsl:template match="osfingerprint">
  <xsl:variable name="var_address" select="../../address/@addr" /> 
  <xsl:choose>
    <xsl:when test="count(../osmatch)=0">
      <ul style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
        <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Cannot determine exact operating system.  Fingerprint provided below.</li>
        <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">If you know what OS is running on it, see https://nmap.org/submit/</li>
      </ul>
      <table cellspacing="0.5">
        <tr style="color:#000;background-color:#ddd;text-align:left;padding:0;vertical-align:top;" class="head">
          <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;font-weight: bold;line-height:16px;font-family:Arial;">Operating System fingerprint</p></td>
        </tr>
        <tr>
          <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><pre><xsl:value-of select="@fingerprint" /></pre></p></td>
        </tr>
      </table>
    </xsl:when>
    <xsl:otherwise>
      <ul style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
        <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">OS identified but the fingerprint was requested at scan time.</li>
      </ul>
      <xsl:element name="p">
        <xsl:attribute name="id">osblock_<xsl:value-of select="$var_address"/></xsl:attribute>
        <table class="noprint" cellspacing="0.5">
          <tr style="color:#000;background-color:#ddd;text-align:left;padding:0;vertical-align:top;" class="head">
            <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Operating System fingerprint</p></td>
          </tr>
          <tr>
            <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><pre><xsl:value-of select="@fingerprint" /></pre></p></td>
          </tr>
        </table>      
      </xsl:element>
    </xsl:otherwise>
  </xsl:choose>
  </xsl:template>
<!-- ............................................................ -->
<!-- Pre-Scan script -->
<!-- ............................................................ -->
<xsl:template match="prescript">
  <xsl:element name="a">
    <xsl:attribute name="name">prescript</xsl:attribute>
  </xsl:element>
  <h2 style="color:#fff; background-color:#000842; margin:3px 0 3px 0;font-size:24px;line-height:36px;font-family:Arial;">Pre-Scan Script Output</h2>
  <table>
    <tr style="color:#000;background-color:#ddd;text-align:left;padding:0;vertical-align:top;" class="head">
      <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Script Name</p></td>
      <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Output</p></td>
    </tr>
    <xsl:for-each select="script">
    <tr class="script">
      <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
        <xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
      </p></td>
      <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
        <pre>
          <xsl:value-of select="@output"/> <xsl:text></xsl:text>
        </pre>
      </p></td>
    </tr>
  </xsl:for-each>
  </table>
</xsl:template>
<!-- ............................................................ -->
<!-- Post-Scan script -->
<!-- ............................................................ -->
<xsl:template match="postscript">
  <xsl:element name="a">
    <xsl:attribute name="name">postscript</xsl:attribute>
  </xsl:element>
  <h2 style="color:#fff; background-color:#000842; margin:3px 0 3px 0;font-size:24px;line-height:36px;font-family:Arial;">Post-Scan Script Output</h2>
  <table>
    <tr style="color:#000;background-color:#ddd;text-align:left;padding:0;vertical-align:top;" class="head">
      <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Script Name</p></td>
      <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Output</p></td>
    </tr>
  <xsl:for-each select="script">
    <tr class="script">
      <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
        <xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
      </p></td>
      <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
        <pre>
          <xsl:value-of select="@output"/> <xsl:text></xsl:text>
        </pre>
      </p></td>
    </tr>
  </xsl:for-each>
  </table>
</xsl:template>
<!-- ............................................................ -->
<!-- Host Script Scan -->
<!-- ............................................................ -->
<xsl:template match="hostscript">
  <h3 style="color:#fff; background-color:#003366; margin:2px 0 2px 0;font-size:16px;line-height:24px;font-family:Arial;">Host Script Output</h3>
    <table>
      <tr style="color:#000;background-color:#ddd;text-align:left;padding:0;vertical-align:top;" class="head">
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Script Name</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Output</p></td>
      </tr>
  <xsl:for-each select="script">
      <tr class="script">
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
          <xsl:value-of select="@id"/> <xsl:text>&#xA0;</xsl:text>
        </p></td>
        <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
          <pre>
            <xsl:value-of select="@output"/> <xsl:text>&#xA0;</xsl:text>
          </pre>
        </p></td>
      </tr>
  </xsl:for-each>
    </table>
</xsl:template>
<!-- ............................................................ -->
<!-- smurf -->
<!-- ............................................................ -->
<xsl:template match="smurf">
  <xsl:if test="@responses != ''"><h3 style="color:#fff; background-color:#003366; margin:2px 0 2px 0;font-size:16px;line-height:24px;font-family:Arial;">Smurf Responses</h3>
    <ul style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">
      <li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@responses" /> responses counted</li>
    </ul>
  </xsl:if>
</xsl:template>
<!-- ............................................................ -->
<!-- traceroute -->
<!-- ............................................................ -->
<xsl:template match="trace">
  <xsl:if test="@port">
  <xsl:variable name="var_address" select="../address/@addr" /> 
  <xsl:element name="p">
    <xsl:attribute name="id">trace_<xsl:value-of select="$var_address"/></xsl:attribute>
    <xsl:choose>
      <xsl:when test="@port">
        <ul style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><li style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Traceroute data generated using port <xsl:value-of select="@port" />/<xsl:value-of select="@proto" /></li></ul>
      </xsl:when>
    </xsl:choose>
    <table cellspacing="0.5">
      <tr style="color:#000;background-color:#ddd;text-align:left;padding:0;vertical-align:top;" class="head">
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Hop</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Rtt</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">IP</p></td>
        <td style="color:#000;background-color:#ddd;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">Host</p></td>
      </tr>
      <xsl:for-each select="hop">
        <xsl:choose>
            <xsl:when test="@rtt = '--'">
              <tr class="filtered">
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@ttl" /></p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;">--</p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@ipaddr" /></p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@host" /></p></td>
              </tr>
            </xsl:when>
            <xsl:when test="@rtt > 0">
              <tr class="open">
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@ttl" /></p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@rtt" /></p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@ipaddr" /></p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@host" /></p></td>
              </tr>
            </xsl:when>
            <xsl:otherwise>
              <tr class="closed">
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"><xsl:value-of select="@ttl" /></p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"></p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"></p></td>
                <td style="color:#000;background-color:#fff;text-align:left;"><p style="margin:1px 0 1px 0;font-size:12px;line-height:16px;font-family:Arial;"></p></td>
              </tr>
            </xsl:otherwise>
          </xsl:choose>
      </xsl:for-each>
    </table>
  </xsl:element>
  </xsl:if>
</xsl:template>
</xsl:stylesheet>
