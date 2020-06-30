# Upnp BHunter
#
# Simple Burp plugin which could be useful to find active UPnP services/devices
# and extract the related SOAP, Subscribe and Presentation requests 
# (both IPv4 and IPv6 are supported).
#
# Copyright (C) 2019 Maurizio Siddu
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>



from burp import (IBurpExtender, ITab, IExtensionStateListener, IScanIssue, IHttpService, IHttpRequestResponse)
from javax.swing import (SwingUtilities, JSplitPane, JProgressBar, GroupLayout, BorderFactory, JPanel, JTextField, JLabel, JButton, JComboBox)
from javax.swing.border import EmptyBorder
from java.net import URL
from java.lang import (Runnable, Short)
from java.awt import (FlowLayout, BorderLayout, Font, Color, Dimension, GridLayout)
import re
import threading
import socket
import select
from urlparse import urlparse
import errno
import urllib2
from java.awt.event import ActionListener




class PyRunnable(Runnable):
    # Class used to wrap a python callable object into a Java Runnable that is 
    # suitable to be passed to various Java methods that perform callbacks
    def __init__(self, target, *args, **kwargs):
        # Create a PyRunnable instance
        self.target = target  # python object to call
        self.args = args      # positional arguments
        self.kwargs = kwargs  # keywoard arguments
    
    def run(self):
        self.target(*self.args, **self.kwargs)




class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):#, IScanIssue, IHttpService):
    # Define the global variables for the burp plugin
    EXTENSION_NAME = "UPnP BHunter"
    ipv4_selected = True
    all_SOAPs, LAN_SOAPs, WAN_SOAPs, all_Subs, all_Pres = {}, {}, {}, {}, {}
    all_SOAP_list, LAN_SOAP_list, WAN_SOAP_list, Sub_list, Pres_list = [], [], [], [], []
    STOP_THREAD = False
    scope_dict = {}
    #Some  SSDP m-search parameters are based upon "UPnP Device Architecture v2.0"
    SSDP_MULTICAST_IPv4 = ["239.255.255.250"]
    SSDP_MULTICAST_IPv6 = ["FF02::C", "FF05::C"]
    SSDP_MULTICAST_PORT = 1900
    ST_ALL = "ssdp:all"
    ST_ROOTDEV = "upnp:rootdevice"
    PLACEHOLDER = "FUZZ_HERE"
    SSDP_TIMEOUT = 2
    issues_dict = {}




    def registerExtenderCallbacks(self, callbacks):
        # Get a reference to callbacks object
        self.callbacks = callbacks
        # Get the useful extension helpers object
        self.helpers = callbacks.getHelpers()
        # Set the extension name
        self.callbacks.setExtensionName(self.EXTENSION_NAME)
        self.callbacks.registerExtensionStateListener(self)
        # Draw plugin user interface
        self.drawPluginUI()
        self.callbacks.addSuiteTab(self)
        # Plugin loading message
        print("[+] Burp plugin UPnP BHunter loaded successfully")
        return




    def publishUpnpDetectionIssue(self):
        # Check and publish found UPnP issues
        if self.issues_dict:
            for loc_url in self.issues_dict:
                # First publish the UPnP service detected issue
                loc_url_parsed = urlparse(loc_url)
                protocol = loc_url_parsed.scheme.encode('ascii','ignore')
                host = loc_url_parsed.netloc.split(":")[0].encode('ascii','ignore')
                port = loc_url_parsed.netloc.split(":")[1]
                path = loc_url_parsed.path.encode('ascii','ignore')
                upnp_url = URL(protocol + "://" + host + ":" + unicode(port) + path)
                httpService = CustomIHttpService(protocol, host, int(port))
                comment = None
                highlight = None
                server_id = self.issues_dict[loc_url]["server_id"]
                # Create upnp detection issue
                upnp_issue = CustomScanIssue(CustomIHttpService(protocol, host, int(port)), 
                    upnp_url, 
                    "UPnP Service Detected", 
                    "The remote host has an active UPnP service and the following server header was identified:<ul><li>"+server_id+"</li></ul>",
                    "Certain", 
                    "Information",
                    "UPnP (Universal Plug and Play) is a protocol that allows communication between computers and network-enabled devices, enabled by default on various systems (e.g. routers, IoT devices, printers, etc.).<br><br> \
                    This protocol was not designed with security in mindset, and UPnP devices/applications could be afflicted by various security issues related to protocol implemetations, programming errors and misconfigurations.<br><br> \
                    For example UPnP services rarely are protected by an authentication mechanism, privileged functionalities are often exposed to untrusted networks, \
                    UPnP devices often are running not alligned with latest security patches, and common programming flaws plague some UPnP software implementations.<br><br> \
                    Consequences could be catastrophic as: access to internal network bypassing firewall rules, abuse the UPnP device for DDoS attacks, Privilege Escalations, Buffer Overflows, RCEs, data exfiltrations, etc.<br><br> \
                    References:<br><ul><li><a href=\"https://openconnectivity.org/developer/specifications/upnp-resources/upnp/\">https://openconnectivity.org/developer/specifications/upnp-resources/upnp/</a></li><li> \
                    <a href=\"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=upnp\">https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=upnp</a></li> \
                    <li><a href=\"https://www.blackhat.com/presentations/bh-usa-08/Squire/BH_US_08_Squire_A_Fox_in_the_Hen_House%20White%20Paper.pdf\">https://www.blackhat.com/presentations/bh-usa-08/Squire/BH_US_08_Squire_A_Fox_in_the_Hen_House%20White%20Paper.pdf</a></li> \
                    <li><a href=\"https://routersecurity.org/testrouter.php#UPnPtesters\">https://routersecurity.org/testrouter.php#UPnPtesters</a></li></ul>",
                    "Disable UPnP service if it is not a business or technical requirement. Otherwise at least disable unsecured UPnP services on Internet or DMZ nets."
                    )
                # Add the new issue on Burp dashboard
                self.callbacks.addScanIssue(upnp_issue)
        return




    def publishUpnpFunctionIssues(self):
        # Check and publish the found UPnP issues
        if self.issues_dict:
            for loc_url in self.issues_dict:
                loc_url_parsed = urlparse(loc_url)
                protocol = loc_url_parsed.scheme.encode('ascii','ignore')  
                # The UPnP Privileged Profile issue
                if self.LAN_SOAP_list or self.WAN_SOAP_list:
                    url = self.issues_dict[loc_url]["ctrl_URL"]
                    url_parsed = urlparse(url)
                    protocol = url_parsed.scheme.encode('ascii','ignore')
                    host = url_parsed.netloc.split(":")[0].encode('ascii','ignore')
                    port = url_parsed.netloc.split(":")[1]
                    path = url_parsed.path.encode('ascii','ignore')
                    igd_url = URL(protocol + "://" + host + ":" + unicode(port) + path) 
                    # Create upnp privileged IGD profile issue                        
                    igd_issue = CustomScanIssue(CustomIHttpService(protocol, host, int(port)), 
                    igd_url, 
                    "UPnP Privileged IGD Profile Detected", 
                    "The UPnP service exposes some of the IGD privileged profiles: \"LANHostConfigManagement\", \"WANIPConnection\" or \"WANPPPConnection\".",
                    "Certain", 
                    "Information",
                    "The UPnP profiles \"LANHostConfigManagement\", \"WANIPConnection\" and \"WANPPPConnection\" provide some interesting IGD features that allow to change routing settings of UPnP devices.<br><br> \
                    IGD profiles have to be carefully secured, in order to avoid abuses which could lead to unauthorized actions, as for example expose internal hosts to external networks bypassing firewall restrictions.<br><br> \
                    References:<br><ul><li><a href=\"http://www.upnp-hacks.org/\">http://www.upnp-hacks.org/</a></li><li><a href=\"https://www.blackhat.com/presentations/bh-usa-08/Squire/BH_US_08_Squire_A_Fox_in_the_Hen_House%20White%20Paper.pdf\"> \
                    https://www.blackhat.com/presentations/bh-usa-08/Squire/BH_US_08_Squire_A_Fox_in_the_Hen_House%20White%20Paper.pdf</a></li></ul> ",
                    "Disable UPnP service if it is not a business or technical requirement. The UPnP sensitive features as IGD profiles must be protected from unauthorized accesses and abuses."
                    ) 
                    # Add the new issue on Burp dashboard
                    self.callbacks.addScanIssue(igd_issue)

                # The UPnP Subscribe issue
                if self.Sub_list:
                    url = self.issues_dict[loc_url]["subs_URL"]
                    url_parsed = urlparse(url)
                    protocol = url_parsed.scheme.encode('ascii','ignore')
                    host = url_parsed.netloc.split(":")[0].encode('ascii','ignore')
                    port = url_parsed.netloc.split(":")[1]
                    path = url_parsed.path.encode('ascii','ignore')
                    sub_url = URL(protocol + "://" + host + ":" + unicode(port) + path) 
                    # Create upnp subscribe issue
                    sub_issue = CustomScanIssue(CustomIHttpService(protocol, host, int(port)), 
                    sub_url, 
                    "UPnP Subscribe Method Detected", 
                    "The UPnP service allows Event Subscription.",
                    "Certain", 
                    "Information",
                    "The UPnP method \"Subscribe\" allows to receive event messages from UPnP devices when some state variables are updated, to an HTTP listening host specified by the subscriber.<br><br> \
                    This service should be carefully secured in order to avoid abuses which could lead to unauthorized actions, as for example send event messages to arbitrary destinations for DDoS attacks.<br><br> \
                    References:<br><ul><li><a href=\"http://www.upnp-hacks.org/sane2006-paper.pdf\">http://www.upnp-hacks.org/sane2006-paper.pdf</a></li><li><a href=\"https://resources.infosecinstitute.com/ddos-upnp-devices/\"> \
                    https://resources.infosecinstitute.com/ddos-upnp-devices/</a></li><li><a href=\"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12695\">https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-12695</a></li></ul>",
                    "Disable UPnP service if it is not a business or technical requirement. The UPnP methods as Subscribe must be protected from unauthorized accesses and abuses."
                    ) 
                    # Add the new issue on Burp dashboard
                    self.callbacks.addScanIssue(sub_issue)

                # The UPnP Presentation issue
                if self.Pres_list:
                    url = self.issues_dict[loc_url]["pres_URL"]
                    url_parsed = urlparse(url)
                    protocol = url_parsed.scheme.encode('ascii','ignore')
                    host = url_parsed.netloc.split(":")[0].encode('ascii','ignore')
                    if ":" in url_parsed.netloc:
                        port = url_parsed.netloc.split(":")[1]
                    else:
                        port = '80'
                    path = url_parsed.path.encode('ascii','ignore')
                    pres_url = URL(protocol + "://" + host + ":" + unicode(port) + path) 
                    # Create upnp presentation issue
                    pres_issue = CustomScanIssue(CustomIHttpService(protocol, host, int(port)), 
                    pres_url, 
                    "UPnP Presentation Method Detected", 
                    "The UPnP service exposes a Presentation web page.",
                    "Certain", 
                    "Information",
                    "The UPnP method \"Presentation\" allows UPnP devices to expose an web page, depending on the vendor specific implementations this presentation page could allow users to control the device and view its status.<br><br> \
                    This service should be carefully secured in order to avoid abuses which could lead to unauthorized actions.<br><br> \
                    References:<br><ul><li><a href=\"http://www.upnp-hacks.org/\">http://www.upnp-hacks.org/</a></li></li><li><a href=\"https://cwe.mitre.org/data/definitions/200.html\">https://cwe.mitre.org/data/definitions/200.html</a></li></ul>",
                    "Disable UPnP service if it is not a business or technical requirement. The UPnP methods as Presentation must be protected from unauthorized accesses and abuses."
                    ) 
                    # Add the new issue on Burp dashboard
                    self.callbacks.addScanIssue(pres_issue)
        
        return
        



    def drawPluginUI(self):
        # Create the plugin user interface
        self.pluginTab = JPanel()
        self.uiTitle = JLabel('UPnP BHunter Load, Aim and Fire Console')
        self.uiTitle.setFont(Font('Tahoma', Font.BOLD, 14))
        self.uiTitle.setForeground(Color(250,100,0))
        self.uiPanelA = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.uiPanelA.setMaximumSize(Dimension(2500, 1000))
        self.uiPanelA.setDividerSize(2)
        self.uiPanelB = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.uiPanelB.setDividerSize(2)
        self.uiPanelA.setBottomComponent(self.uiPanelB)
        self.uiPanelA.setBorder(BorderFactory.createLineBorder(Color.gray))

        # Create and configure labels and text fields
        self.labeltitle_step1 = JLabel("[1st STEP] Discover UPnP Locations")
        self.labeltitle_step1.setFont(Font('Tahoma', Font.BOLD, 14))
        self.labeltitle_step2 = JLabel("[2nd STEP] Select an UPnP Service")
        self.labeltitle_step2.setFont(Font('Tahoma', Font.BOLD, 14))
        self.labeltitle_step3 = JLabel("[3rd STEP] Time to Attack it")
        self.labeltitle_step3.setFont(Font('Tahoma', Font.BOLD, 14))
        self.labelsubtitle_step1 = JLabel("Specify the IP version address in scope and start UPnP discovery")
        self.labelsubtitle_step2 = JLabel("Select which of the found UPnP services will be probed")
        self.labelsubtitle_step3 = JLabel("Select how to test the extracted UPnP service requests")
        self.label_step1 = JLabel("Target IP")
        self.label_step2 = JLabel("Found UPnp Services")
        self.label_step3 = JLabel("Send all the extracted SOAP requests     ")
        self.labelstatus = JLabel("             Status")

        self.labelempty_step1 = JLabel("                ")
        self.labelempty_step2 = JLabel("  ")
        self.labelupnp = JLabel("    UPnP list")
        self.labelip = JLabel("IP list")
        self.labelLANHOST = JLabel("Send the interesting LANHostConfigManagement SOAP requests     ")
        self.labelWANCONNECTION = JLabel("Send the interesting WANIP/PPPConnection SOAP requests     ")
        self.labelSubscribe = JLabel("Send the Subscribe requests     ")
        self.labelPresentation = JLabel("Send the Presentation requests     ")
        self.labelSOAPnum = JLabel("0")
        self.labelLANHOSTnum = JLabel("0")
        self.labelWANCONNECTIONnum = JLabel("0")
        self.labelSubnum = JLabel("0")
        self.labelPresnum = JLabel("0")
        self.labelNoneServiceFound = JLabel("  ")
        self.labelNoneServiceFound.setFont(Font('Tahoma', Font.BOLD, 12))
        self.labelNoneServiceFound.setForeground(Color.red)

        # Create combobox for IP version selection 
        self.ip_versions = ["IPv4", "IPv6"]
        self.combo_ipversion = JComboBox(self.ip_versions)
        self.combo_ipversion.setSelectedIndex(0)
        self.combo_ipversion.setEnabled(True)

        # Create and configure progress bar
        self.progressbar = JProgressBar(0,100)
        self.progressbar.setString("Ready")
        self.progressbar.setStringPainted(True)

        # Create and configure buttons
        self.startbutton = JButton("Start Discovery", actionPerformed=self.startHunting)
        self.clearbutton = JButton("Clear All", actionPerformed=self.clearAll)
        self.confirmbutton = JButton("Confirm Selection", actionPerformed=self.selectUPnPService)
        self.intruderbutton = JButton("to Intruder", actionPerformed=self.sendUPnPToIntruder)
        self.LANrepeaterbutton = JButton("to Repeater", actionPerformed=self.sendLANUPnPToRepeater)
        self.WANrepeaterbutton = JButton("to Repeater", actionPerformed=self.sendWANUPnPToRepeater)
        self.Subrepeaterbutton = JButton("to Repeater", actionPerformed=self.sendSubUPnPToRepeater)
        self.Presrepeaterbutton = JButton("to Repeater", actionPerformed=self.sendPresUPnPToRepeater)

        self.confirmbutton.setEnabled(False)
        self.intruderbutton.setEnabled(False)
        self.LANrepeaterbutton.setEnabled(False)
        self.WANrepeaterbutton.setEnabled(False)
        self.Subrepeaterbutton.setEnabled(False)
        self.Presrepeaterbutton.setEnabled(False)        

        # Create the combo box, select item at index 0 (first item in list)
        self.upnpservices = ["       "]
        self.upnpcombo_services = JComboBox(self.upnpservices)
        self.upnpcombo_services.setSelectedIndex(0)
        self.upnpcombo_services.setEnabled(False)

        # Class neeeded to handle the combobox in second step panel
        class ComboboxListener(ActionListener):
            def __init__(self, upnpcombo_targets, upnpcombo_services, scope_dict):
                self.upnpcombo_targets = upnpcombo_targets
                self.upnpcombo_services = upnpcombo_services
                self.scope_dict = scope_dict
            def actionPerformed(self, event):
                # Update the location url combobox depending on the IP combobox 
                selected_target = self.upnpcombo_targets.getSelectedItem()
                if self.scope_dict and selected_target:
                    self.upnpcombo_services.removeAllItems()
                    for scope_url in self.scope_dict[selected_target]:
                        self.upnpcombo_services.addItem(scope_url)
                    self.upnpcombo_services.setSelectedIndex(0)

        # Create the combo box, select item at index 0 (first item in list)
        self.upnptargets = ["       "]
        self.upnpcombo_targets = JComboBox(self.upnptargets)
        self.upnpcombo_targets.setSelectedIndex(0)
        self.upnpcombo_targets.setEnabled(False)
        self.upnpcombo_targets.addActionListener(ComboboxListener(self.upnpcombo_targets,self.upnpcombo_services,self.scope_dict))

        # Configuring first step panel
        self.panel_step1 = JPanel()
        self.panel_step1.setPreferredSize(Dimension(2250, 100))
        self.panel_step1.setBorder(EmptyBorder(10,10,10,10))
        self.panel_step1.setLayout(BorderLayout(15,15))
        self.titlepanel_step1 = JPanel()
        self.titlepanel_step1.setLayout(BorderLayout())
        self.titlepanel_step1.add(self.labeltitle_step1,BorderLayout.NORTH)
        self.titlepanel_step1.add(self.labelsubtitle_step1)
        self.targetpanel_step1 = JPanel()
        self.targetpanel_step1.add(self.label_step1)
        self.targetpanel_step1.add(self.combo_ipversion)
        self.targetpanel_step1.add(self.startbutton)
        self.targetpanel_step1.add(self.clearbutton)
        self.targetpanel_step1.add(self.labelstatus)
        self.targetpanel_step1.add(self.progressbar)
        self.emptypanel_step1 = JPanel()
        self.emptypanel_step1.setLayout(BorderLayout())
        self.emptypanel_step1.add(self.labelempty_step1,BorderLayout.WEST)

        # Assembling first step panel components
        self.panel_step1.add(self.titlepanel_step1,BorderLayout.NORTH)
        self.panel_step1.add(self.targetpanel_step1,BorderLayout.WEST)
        self.panel_step1.add(self.emptypanel_step1,BorderLayout.SOUTH)
        self.uiPanelA.setTopComponent(self.panel_step1)

        # Configure second step panel
        self.panel_step2 = JPanel()
        self.panel_step2.setPreferredSize(Dimension(2250, 100))
        self.panel_step2.setBorder(EmptyBorder(10,10,10,10))
        self.panel_step2.setLayout(BorderLayout(15,15))
        self.titlepanel_step2 = JPanel()
        self.titlepanel_step2.setLayout(BorderLayout())
        self.titlepanel_step2.add(self.labeltitle_step2,BorderLayout.NORTH)
        self.titlepanel_step2.add(self.labelsubtitle_step2)
        self.selectpanel_step2 = JPanel()
        self.selectpanel_step2.add(self.labelip)
        self.selectpanel_step2.add(self.upnpcombo_targets)
        self.selectpanel_step2.add(self.labelupnp)
        self.selectpanel_step2.add(self.upnpcombo_services)
        self.selectpanel_step2.add(self.confirmbutton)
        self.emptypanel_step2 = JPanel()
        self.emptypanel_step2.setLayout(BorderLayout())
        self.emptypanel_step2.add(self.labelempty_step2,BorderLayout.WEST)
        self.emptypanel_step2.add(self.labelNoneServiceFound)

        # Assembling second step panel components
        self.panel_step2.add(self.titlepanel_step2,BorderLayout.NORTH)
        self.panel_step2.add(self.selectpanel_step2,BorderLayout.WEST)
        self.panel_step2.add(self.emptypanel_step2,BorderLayout.SOUTH)
        self.uiPanelB.setTopComponent(self.panel_step2) 

        # Configuring third step panel
        self.panel_step3 = JPanel()
        self.panel_step3.setPreferredSize(Dimension(2250, 100))
        self.panel_step3.setBorder(EmptyBorder(10,10,10,10))
        self.panel_step3.setLayout(BorderLayout(15,15))
        self.titlepanel_step3 = JPanel()
        self.titlepanel_step3.setLayout(BorderLayout())
        self.titlepanel_step3.add(self.labeltitle_step3,BorderLayout.NORTH)
        self.titlepanel_step3.add(self.labelsubtitle_step3)
        self.underpanel_step3 = JPanel()

        underlayout = GroupLayout(self.underpanel_step3)
        self.underpanel_step3.setLayout(underlayout)
        underlayout.setAutoCreateGaps(True)
        underlayout.setAutoCreateContainerGaps(True)
        left2right = underlayout.createSequentialGroup()
        firstcolumn = underlayout.createParallelGroup()
        firstcolumn.addComponent(self.label_step3, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
        firstcolumn.addComponent(self.labelLANHOST, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
        firstcolumn.addComponent(self.labelWANCONNECTION, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
        firstcolumn.addComponent(self.labelSubscribe, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
        firstcolumn.addComponent(self.labelPresentation, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)

        secondcolumn = underlayout.createParallelGroup()
        secondcolumn.addComponent(self.labelSOAPnum)
        secondcolumn.addComponent(self.labelLANHOSTnum)
        secondcolumn.addComponent(self.labelWANCONNECTIONnum)
        secondcolumn.addComponent(self.labelSubnum)
        secondcolumn.addComponent(self.labelPresnum)

        thirdcolumn = underlayout.createParallelGroup()
        thirdcolumn.addComponent(self.intruderbutton)
        thirdcolumn.addComponent(self.LANrepeaterbutton)
        thirdcolumn.addComponent(self.WANrepeaterbutton)
        thirdcolumn.addComponent(self.Subrepeaterbutton)
        thirdcolumn.addComponent(self.Presrepeaterbutton)

        left2right.addGroup(firstcolumn)
        left2right.addGroup(secondcolumn)
        left2right.addGroup(thirdcolumn)
        top2bottom = underlayout.createSequentialGroup()
        firstrow = underlayout.createParallelGroup()
        firstrow.addComponent(self.label_step3, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)       
        firstrow.addComponent(self.labelSOAPnum)        
        firstrow.addComponent(self.intruderbutton)
        secondrow = underlayout.createParallelGroup()
        secondrow.addComponent(self.labelLANHOST, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)        
        secondrow.addComponent(self.labelLANHOSTnum)
        secondrow.addComponent(self.LANrepeaterbutton)       
        thirdrow = underlayout.createParallelGroup()
        thirdrow.addComponent(self.labelWANCONNECTION, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)        
        thirdrow.addComponent(self.labelWANCONNECTIONnum) 
        thirdrow.addComponent(self.WANrepeaterbutton)
        fourthrow = underlayout.createParallelGroup()
        fourthrow.addComponent(self.labelSubscribe, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)        
        fourthrow.addComponent(self.labelSubnum) 
        fourthrow.addComponent(self.Subrepeaterbutton)
        fifthrow = underlayout.createParallelGroup()
        fifthrow.addComponent(self.labelPresentation, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)        
        fifthrow.addComponent(self.labelPresnum) 
        fifthrow.addComponent(self.Presrepeaterbutton)

        top2bottom.addGroup(firstrow)
        top2bottom.addGroup(secondrow)
        top2bottom.addGroup(thirdrow)
        top2bottom.addGroup(fourthrow)
        top2bottom.addGroup(fifthrow)

        underlayout.setHorizontalGroup(left2right)
        underlayout.setVerticalGroup (top2bottom)

        # Assembling thirdd step panel components
        self.panel_step3.add(self.titlepanel_step3,BorderLayout.NORTH)
        self.panel_step3.add(self.underpanel_step3,BorderLayout.WEST)
        self.uiPanelB.setBottomComponent(self.panel_step3) 

        # Assembling the group of all panels
        layout = GroupLayout(self.pluginTab)
        self.pluginTab.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(10, 10, 10)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self.uiTitle)
                    .addGap(15,15,15)
                    .addComponent(self.uiPanelA)
                    )
                .addContainerGap(26, Short.MAX_VALUE)))
        layout.setVerticalGroup (
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(15,15,15)
                .addComponent(self.uiTitle)
                .addGap(15,15,15)
                .addComponent(self.uiPanelA)
                .addGap(20,20,20)
                .addGap(20,20,20)))




    def extensionUnloaded(self):
        # Unload the plugin, and if running stop the background thread
        if self.upnpcombo_services.isEnabled():
            if self.th.isAlive():
                print("[+] Stopping thread %s") % self.th.getName()
                self.STOP_THREAD = True
                self.th.join()
            else:
                print("Thread %s already dead") % self.th.getName()
        print("[+] Burp plugin UPnP BHunter successfully unloaded")
        return

    


    def getTabCaption(self):
        return self.EXTENSION_NAME




    def getUiComponent(self):
        return self.pluginTab




    def clearAll(self, e=None):
        # Reset all data of the plugin
        self.all_SOAPs, self.LAN_SOAPs, self.WAN_SOAPs, self.all_Subs, self.all_Pres = {}, {}, {}, {}, {}
        self.all_SOAP_list, self.LAN_SOAP_list, self.WAN_SOAP_list, self.Sub_list, self.Pres_list = [], [], [], [], []
        self.progressbar.setString("Ready")
        self.progressbar.setValue(0)
        self.upnpcombo_targets.removeAllItems()
        self.upnpcombo_targets.setEnabled(False)
        self.upnpcombo_services.removeAllItems()
        self.upnpcombo_services.setEnabled(False)
        self.confirmbutton.setEnabled(False)
        self.intruderbutton.setEnabled(False)
        self.labelSOAPnum.setText("0")
        self.LANrepeaterbutton.setEnabled(False)
        self.labelLANHOSTnum.setText("0")
        self.WANrepeaterbutton.setEnabled(False)
        self.labelWANCONNECTIONnum.setText("0")
        self.Subrepeaterbutton.setEnabled(False)
        self.labelSubnum.setText("0")
        self.Presrepeaterbutton.setEnabled(False)
        self.labelPresnum.setText("0")
        self.labelNoneServiceFound.setText(" ")
        print("[+] Clearing all data")
        return




    def startHunting (self, e=None):
        # Starting the UPnP hunt
        def startHunting_run():
            # Initialize the internal parameters every time the start-discovery button is clicked
            self.all_SOAPs, self.LAN_SOAPs, self.WAN_SOAPs, self.all_Subs, self.all_Pres = {}, {}, {}, {}, {}
            self.all_SOAP_list, self.LAN_SOAP_list, self.WAN_SOAP_list, self.Sub_list, self.Pres_list = [], [], [], [], []
            found_loc = []
            self.labelNoneServiceFound.setText(" ")
            self.intruderbutton.setEnabled(False)
            self.labelSOAPnum.setText("0")
            self.LANrepeaterbutton.setEnabled(False)
            self.labelLANHOSTnum.setText("0")
            self.WANrepeaterbutton.setEnabled(False)
            self.labelWANCONNECTIONnum.setText("0")
            self.Subrepeaterbutton.setEnabled(False)
            self.labelSubnum.setText("0")
            self.Presrepeaterbutton.setEnabled(False)
            self.labelPresnum.setText("0")
            
            # Then determine if targerting IPv4 or IPv6 adresses
            if self.combo_ipversion.getSelectedItem() == "IPv4":
                self.ipv4_selected = True
                print("[+] Selected IPv4 address scope")                
            else:
                self.ipv4_selected = False
                print("[+] Selected IPv6 address scope")

            # And here finally the hunt could start
            self.progressbar.setString("Running...")
            self.progressbar.setValue(20)
            found_loc = self.discoverUpnpLocations()
            self.progressbar.setValue(40)
            discovery_files = self.downloadXMLfiles(found_loc)
            self.progressbar.setValue(60)
            self.all_SOAPs,self.LAN_SOAPs,self.WAN_SOAPs = self.buildSOAPs(discovery_files)
            self.all_Subs = self.buildSubscribes(discovery_files)
            self.all_Pres = self.buildPresentations(discovery_files)
            self.progressbar.setValue(80)
            self.progressbar.setString("Done")
            self.progressbar.setValue(100)
            # Update the comboboxes list with the discovered UPnPs
            self.upnpcombo_targets.setEnabled(True)
            self.upnpcombo_services.setEnabled(True)           
            self.updateComboboxList(found_loc)
            # Check and publish UpnP service detection issue
            self.publishUpnpDetectionIssue()

            if self.STOP_THREAD:
                return

        # Start a background thread to run the above nested function in order to prevent the blocking of plugin UI
        self.th = threading.Thread(target=startHunting_run)
        #self.th.daemon = True    # This does not seem to be useful
        self.th.setName("th-BHunter")
        self.th.start()




    def ssdpReqBuilder(self, ssdp_timeout, st_type, ssdp_ip, ssdp_port):
        # Builder of the two ssdp msearch request types
        msearch_req = "M-SEARCH * HTTP/1.1\r\n" \
        "HOST: {0}:{1}\r\n" \
        "MAN: \"ssdp:discover\"\r\n" \
        "MX: {2}\r\n" \
        "ST: {3}\r\n" \
        "\r\n" \
        .format(ssdp_ip, ssdp_port, ssdp_timeout, st_type)
        return msearch_req




    def sendMsearch(self, ssdp_req, ssdp_ip, ssdp_port):
        # Send the ssdp request and retrieve response
        buf_resp = set()
        if self.ipv4_selected:
            print("[+] Creating IPv4 SSDP multicast request")
            sock = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
        else:
            print("[+] Creating IPv6 SSDP multicast request")
            sock = socket.socket (socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setblocking(0)
        # Sending ssdp requests
        while len(ssdp_req):
            # Blocking socket client until the request is completely sent
            try:
                sent = sock.sendto(ssdp_req.encode("ASCII"), (ssdp_ip, ssdp_port))
                ssdp_req = ssdp_req[sent:]
            except socket.error, exc:
                if exc.errno != errno.EAGAIN:
                    print("[E] Got error %s with socket when sending") % exc
                    sock.close()
                    raise exc
                print("[!] Blocking socket until ", len(ssdp_req), " is sent.")       
                select.select([], [sock], [])
                continue
        # Retrieving ssdp responses
        num_resp = 0
        while sock:
            # Blocking socket until there are ssdp responses to be read or timeout is reached
            readable, __, __ = select.select([sock], [], [], self.SSDP_TIMEOUT)
            if not readable:
                # Timeout reached without receiving any ssdp response
                if num_resp == 0:
                    print("[!] Got timeout without receiving any ssdp response.")
                break
            else:
                num_resp = num_resp + 1
                # Almost an ssdp response was received
                if readable[0]:
                    try:
                        data = sock.recv(1024)
                        if data:
                            buf_resp.add(data.decode('ASCII'))
                    except socket.error, exc:
                        print("[E] Got error %s with socket when receiving") % exc
                        sock.close()
                        raise exc
        sock.close()
        # Assemblage of the ssdp response from received data chunks
        resp = list(buf_resp)
        return resp




    def discoverUpnpLocations(self):
        # Retrieve a list of UPnP location-urls via ssdp M-SEARCH broadcast request
        locations = set()
        location_regex = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)
        server_regex = re.compile("server:[ ]*(.+)\r\n", re.IGNORECASE)
        # First check if targeting IPv4 or IPv6 addresses
        if self.ipv4_selected:
            # Use two possible type of ssdp requests 
            ssdp_requests = [
            self.ssdpReqBuilder(self.SSDP_TIMEOUT, self.ST_ALL, self.SSDP_MULTICAST_IPv4[0], self.SSDP_MULTICAST_PORT), 
            self.ssdpReqBuilder(self.SSDP_TIMEOUT, self.ST_ROOTDEV, self.SSDP_MULTICAST_IPv4[0], self.SSDP_MULTICAST_PORT)
            ]
            # First try with "Ssdp:All" request type
            print("[+] Start hunting with \"Ssdp:All\" ssdp request type")
            ssdp_responses = self.sendMsearch(ssdp_requests[0], self.SSDP_MULTICAST_IPv4[0], self.SSDP_MULTICAST_PORT)
            # Then try with the alternative "Root:Device" request type
            if not ssdp_responses:
                print("[+] Retrying with \"Root:Device\" ssdp request type")
                ssdp_responses = self.sendMsearch(ssdp_requests[1], self.SSDP_MULTICAST_IPv4[0], self.SSDP_MULTICAST_PORT)
            # Extract location heaader information from ssdp response
            if ssdp_responses:
                for ssdp_resp in ssdp_responses:
                    location_result = location_regex.search(ssdp_resp)
                    server_result = server_regex.search(ssdp_resp)
                    if location_result and (location_result.group(1) in locations) == False:
                        locations.add(location_result.group(1))
                        if server_result:
                            self.issues_dict[location_result.group(1)] = {}
                            self.issues_dict[location_result.group(1)]["server_id"] = server_result.group(1)
            else:
                print("[!] Unsucessfull hunt, no active UPnP service was found. Try with other target IPs")
            upnp_locations = list(locations)
        else:
            # Note: IPv6 addresses in Host header for RFC2732 have to be enclosed between square brackets
            # Use four possible type of ssdp requests cause of IPv6 link-local and site-local adresses to support
            ssdp_requests = [
            self.ssdpReqBuilder(self.SSDP_TIMEOUT, self.ST_ALL, "["+self.SSDP_MULTICAST_IPv6[0]+"]", self.SSDP_MULTICAST_PORT), 
            self.ssdpReqBuilder(self.SSDP_TIMEOUT, self.ST_ROOTDEV, "["+self.SSDP_MULTICAST_IPv6[0]+"]", self.SSDP_MULTICAST_PORT),
            self.ssdpReqBuilder(self.SSDP_TIMEOUT, self.ST_ALL, "["+self.SSDP_MULTICAST_IPv6[1]+"]", self.SSDP_MULTICAST_PORT), 
            self.ssdpReqBuilder(self.SSDP_TIMEOUT, self.ST_ROOTDEV, "["+self.SSDP_MULTICAST_IPv6[1]+"]", self.SSDP_MULTICAST_PORT)
            ]
            # IPv6 link-local section
            # First try with "Ssdp:All" request type
            print("[+] Start hunting with \"Ssdp:All\" ssdp request type")
            ssdp_responses_ll = self.sendMsearch(ssdp_requests[0], self.SSDP_MULTICAST_IPv6[0], self.SSDP_MULTICAST_PORT)
            # Then try with the alternative "Root:Device" request type
            if not ssdp_responses_ll:
                print("[+] Retrying with \"Root:Device\" ssdp request type")
                ssdp_responses_ll = self.sendMsearch(ssdp_requests[1], self.SSDP_MULTICAST_IPv6[0], self.SSDP_MULTICAST_PORT)
            # IPv6 site-local section
            # First try with "Ssdp:All" request type
            print("[+] Start hunting with \"Ssdp:All\" ssdp request type")
            ssdp_responses_sl = self.sendMsearch(ssdp_requests[2], self.SSDP_MULTICAST_IPv6[1], self.SSDP_MULTICAST_PORT)
            # Then try with the alternative "Root:Device" request type
            if not ssdp_responses_sl:
                print("[+] Retrying with \"Root:Device\" ssdp request type")
                ssdp_responses_sl = self.sendMsearch(ssdp_requests[3], self.SSDP_MULTICAST_IPv6[1], self.SSDP_MULTICAST_PORT)

            # Extract location heaader information from ssdp response
            if ssdp_responses_ll or ssdp_responses_sl:
                # Merge all IPv6 SSDP responses
                ssdp_responses = ssdp_responses_ll + ssdp_responses_sl
                for ssdp_resp in ssdp_responses:
                    location_result = location_regex.search(ssdp_resp)
                    if location_result and (location_result.group(1) in locations) == False:
                        locations.add(location_result.group(1))
            else:
                print("[!] Unsucessfull hunt, no active UPnP service was found. Try with other target IPs")
            upnp_locations = list(locations)
        # Finally return the discovered locations
        return upnp_locations




    def updateComboboxList(self, cb_list):
        # Update the combobox items after location urls have been found
        def updateComboboxList_run(cb_list):
            scope_list = []
            cb_dict = {}
            # Reinitialize the two comboboxes
            self.upnpcombo_targets.removeAllItems()
            self.upnpcombo_services.removeAllItems()
            # First check if any UPnP service was found
            if not cb_list:
                self.upnpcombo_targets.addItem("No UPnP service found")
                return
            # Build a dict of found IPs and location urls
            for cb_url in cb_list:
                parsed_cb_url = urlparse(cb_url)
                cb_ip = parsed_cb_url.netloc.split(":")[0]
                if cb_ip in cb_dict:
                    # Append the new number to the existing array at this slot
                    cb_dict[cb_ip].append(cb_url)
                else:
                    # Create a new array in this slot
                    cb_dict[cb_ip] = [cb_url]
            # All the found UPnP services are considered in scope
            self.scope_dict.clear()
            for ip in cb_dict:
                self.scope_dict[ip] = cb_dict[ip]
            # Set the found IPs on the ip list combobox
            for scope_ip in self.scope_dict:
                self.upnpcombo_targets.addItem(scope_ip)
            # Set the found location urls in the upnp list combobox
            selected_ip = self.upnpcombo_targets.getSelectedItem()
            self.upnpcombo_services.removeAllItems()
            for scope_url in self.scope_dict[selected_ip]:
                self.upnpcombo_services.addItem(scope_url)
            # Select the first element in the combobox by default
            self.upnpcombo_services.setSelectedIndex(0)
            self.confirmbutton.setEnabled(True)
        # Call the runnable method to update the plugin UI with results
        SwingUtilities.invokeLater(PyRunnable(updateComboboxList_run, cb_list))




    def downloadXMLfiles(self, download_urls):
        # Download the specified xml files
        xml_files_dict = {}
        is_https = True
        download_resp = None
        # First check if list of location urls is empty
        if download_urls:
            for d_url in download_urls:
                # Extract the various location url items
                d_url_parsed = urlparse(d_url)
                if d_url_parsed.scheme == "http":
                    is_https = False
                d_netloc = d_url_parsed.netloc
                d_host = d_netloc.split(":")[0]
                # Determine service port
                if not ":" in d_netloc:
                    d_port = "80"
                else:
                    d_port = d_netloc.split(":")[1]
                # Build the http download requests for IPv4 and IPv6
                if not self.ipv4_selected:
                    # For IPv6 a little workaround with urllib2 is needed at the moment
                    url_ipv6 = d_url_parsed.scheme + "://" + d_host + ":" + d_port + "/" + d_url_parsed.path
                    download_req = urllib2.Request(url_ipv6, None)
                    try:
                        download_resp = urllib2.urlopen(download_req, timeout=2)
                    except urllib2.URLError, e:
                        print("[!] Got timeout issues when requesting %s" % url_ipv6)
                        pass
                    if download_resp and download_resp.code == 200 and download_resp.msg:
                        print("[+] Successfully downloaded xml file \"%s\" ") % d_url
                        # Extract the response body
                        splitted_resp = download_resp.read()
                        if len(splitted_resp) > 1:
                            xml_files_dict[d_url] = splitted_resp
                    else:
                        print("[!] Skipping, failed to retrieve the XML file from: %s ") % d_url
                else:
                    # For IPv4 build the http download requests using Burp functions
                    ba_download_req = self.helpers.buildHttpRequest(URL(d_url_parsed.scheme, d_host, int(d_port), d_url_parsed.path))
                    ba_download_resp = self.callbacks.makeHttpRequest(d_host, int(d_port), is_https, ba_download_req)
                    if ba_download_resp:
                        download_resp = "".join(map(chr, ba_download_resp))
                    okstatus = None
                    if download_resp:
                        okstatus = re.match(r"HTTP[^ ]* 200 OK", download_resp)
                    if okstatus:
                        print("[+] Successfully downloaded xml file \"%s\" ") % d_url
                        # Extract the response body
                        splitted_resp = download_resp.split("\r\n\r\n")
                        if len(splitted_resp) > 1:
                            xml_files_dict[d_url] = splitted_resp[1]
                    else:
                        print("[!] Skipping, failed to retrieve the XML file from: %s ") % d_url
        return xml_files_dict




    def parseXMLfile(self, file_content, location_url, isPresentation):
        # Extract the juicy info from UPnP Description and SCDP xml files
        # Parsing with regexp (yes I known, an xml-parser could be used)
        output_dict = {}
        service_list = []
        action_list = []
        arg_list = []
        ctrl_URL, scpd_URL, subs_URL, pres_URL = None, None, None, None
        # First remove newlines and whitelines from the xml file
        file2parse = re.sub(r"[\r\n\s\t]*","", file_content)
        # Run here when parsing Description files
        if location_url:
            # Parse the Description XML file to extract the info about Services
            base_URL_elem = re.search("<URLBase>(.*?)</URLBase>", file2parse)
            # Retrieve the baseURL item
            if base_URL_elem:
                base_URL = base_URL_elem.groups()[0].rstrip('/')
            else:
                url = urlparse(location_url)
                base_URL = '%s://%s' % (url.scheme, url.netloc)

            # Run here when searching presentation url in Description file
            if isPresentation:
                # Extract presentationURL
                pres_m = re.search("<presentationURL>(.*?)</presentationURL>", file2parse)
                if pres_m:
                    # Check if presentation url is a complete url or only an url path
                    if pres_m.groups()[0].startswith("http"):
                        pres_URL = pres_m.groups()[0]
                    else:
                        if not pres_m.groups()[0].startswith("/"):
                            pres_URL = base_URL + "/" + pres_m.groups()[0]
                        else:
                            pres_URL = base_URL + pres_m.groups()[0]
                    # Aggregate the extracted info
                    output_dict['presentation_upnpbhunter'] = [None, None, None, pres_URL]

            # Run here when searching service urls in Description file
            else:
                service_list = re.findall("<service>(.*?)</service>", file2parse)
                # Retrieve values of serviceType, controlURL, SCDPURL, eventSubURL, and presentationURL
                for serv in service_list:
                    # Extract serviceType
                    service_type = re.search("<serviceType>(.*?)</serviceType>", serv).groups()[0]
                    # Extract controlURL
                    ctrl_m = re.search("<controlURL>(.*?)</controlURL>", serv)        
                    if ctrl_m:
                        # Check if presentation url is a complete url or only an url path
                        if ctrl_m.groups()[0].startswith("http"):
                            ctrl_URL = ctrl_m.groups()[0]
                        else:
                            if not ctrl_m.groups()[0].startswith("/"):
                                ctrl_URL = base_URL + "/" + ctrl_m.groups()[0]
                            else:
                                ctrl_URL = base_URL + ctrl_m.groups()[0]
                    # Extract SCPDURL
                    scpd_m = re.search("<SCPDURL>(.*?)</SCPDURL>", serv)
                    if scpd_m:
                        # Check if presentation url is a complete url or only an url path
                        if scpd_m.groups()[0].startswith("http"):
                            scpd_URL = scpd_m.groups()[0]
                        else:
                            if not scpd_m.groups()[0].startswith("/"):
                                scpd_URL = base_URL + "/" + scpd_m.groups()[0]
                            else:
                                scpd_URL = base_URL + scpd_m.groups()[0]
                    # Extract eventSubURL
                    subs_m = re.search("<eventSubURL>(.*?)</eventSubURL>", serv)
                    if subs_m:
                        # Check if presentation url is a complete url or only an url path
                        if subs_m.groups()[0].startswith("http"):
                            subs_URL = subs_m.groups()[0]
                        else:
                            if not subs_m.groups()[0].startswith("/"):
                                subs_URL = base_URL + "/" + subs_m.groups()[0]
                            else:
                                subs_URL = base_URL + subs_m.groups()[0]
                    # Aggregate the extracted info 
                    output_dict[service_type] = [ctrl_URL, scpd_URL, subs_URL, None]
            
        # Run here when parsing SCDP files
        else:
            # Parse the SCDP xml file to extract the info about Actions
            action_list = re.findall("(<action>.*?)</action>", file2parse)
            # Retrieve action-name and if present the argument-name values
            for act in action_list:
                act_name = re.search("<action>.*?<name>(.*?)</name>", act).groups()[0]
                arg_name = []
                # Determine if is a Get-action or not
                if act_name.startswith("Get"):
                    # Get-action found
                    arg_direction_list= []
                    inFound = False
                    arg_direction_list = re.findall("<argument>.*?<name>(.*?)</name>.*?<direction>(.*?)</direction>", act)
                    # Search direction info for each extracted argument
                    for arg_nm, arg_direction in arg_direction_list:
                        if arg_direction and "in" in arg_direction:
                            # Get-action with input arguments
                            inFound = True
                            # If at leats an input argument is found then remove all output placeholders
                            while "" in arg_name: arg_name.remove("")
                            arg_name.append(arg_nm)
                        else:
                            # Get-action without input arguments are discarded and a empty placeholder is set
                            if not inFound and not "" in arg_name:
                                arg_name.append("")
                else:
                    # Other than Get-action found
                    arg_exists = re.search("<argument>.*?<name>(.*?)</name>", act)
                    if arg_exists:
                        arg_list = re.findall("<argument>.*?<name>(.*?)</name>", act)
                        for arg in arg_list:
                            arg_name.append(arg)
                    else:
                        # Other than Get-action without any argument are discarded and a empty placeholder is set
                        if not "" in arg_name:
                            arg_name.append("")
                output_dict[act_name] = arg_name
        return output_dict





    def soapReqBuilder(self, service_type, ctrl_URL, action_name, arg_list):
        # Build the soap requests for fuzzing purposes
        soap_enc = "http://schemas.xmlsoap.org/soap/encoding/"
        soap_env = "http://schemas.xmlsoap.org/soap/envelope/"
        service_ns = service_type        
        soap_action = service_ns + "#" + action_name
        target_url = urlparse(ctrl_URL)
        soap_ip_port = target_url.netloc
        soap_path = target_url.path
        soap_body_top = "<?xml version=\"1.0\"?>\r\n" \
        "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"{0}\" SOAP-ENV:encodingStyle=\"{1}\">\r\n" \
        "<SOAP-ENV:Body>\r\n" \
        "    <m:{2} xmlns:m=\"{3}\">\r\n" \
        .format(soap_env, soap_enc, action_name, service_ns)
        soap_body_tail = "    </m:{0}>\r\n" \
        "</SOAP-ENV:Body>\r\n" \
        "</SOAP-ENV:Envelope>" \
        .format(action_name)

        # Create the soap body fuzzable section with a recognizable placeholder
        # Note that other insertion points could be fuzzed (e.g. upnp request headers) 
        sfuzz = []
        for arg_name in arg_list:
            if arg_name:
                sfuzz.append("        <{0}>{1}</{0}>".format(arg_name, self.PLACEHOLDER))
            else:
                # In case of Get-action or an action without arguments
                sfuzz.append("{0}".format(self.PLACEHOLDER))
        soap_body_fuzzable = "\r\n".join(sfuzz)

        # Assemblage of the soap body
        soap_body = soap_body_top + soap_body_fuzzable + "\r\n" + soap_body_tail
        
        # Final assemblage of the soap request
        soap_req = "POST {0} HTTP/1.1\r\n" \
        "SOAPAction: \"{1}\"\r\n" \
        "Host: {2}\r\n" \
        "Content-Type: text/xml\r\n" \
        "Content-Length: {3}\r\n" \
        "\r\n" \
        "{4}" \
        .format(soap_path, soap_action, soap_ip_port, len(soap_body), soap_body)
        '''
        EXAMPLE OF BUILT SOAP REQUEST:
        ------------------------------
        POST /upnp/control/WANIPConn1 HTTP/1.1
        SOAPAction: "urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"
        Host: 192.168.1.1:49155
        Content-Type: text/xml
        Content-Length: 437
        
        <?xml version="1.0"?>
        <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
        <SOAP-ENV:Body>
            <m:DeletePortMapping xmlns:m="urn:schemas-upnp-org:service:WANIPConnection:1">
                <NewProtocol>FUZZ_HERE</NewProtocol>
                <NewExternalPort>FUZZ_HERE</NewExternalPort>
                <NewRemoteHost>FUZZ_HERE</NewRemoteHost>
            </m:DeletePortMapping>
        </SOAP-ENV:Body>
        </SOAP-ENV:Envelope>
        '''        
        return soap_req




    def buildSOAPs(self, discovery_files_dict):
        # Retrieve all SOAP requests of the discovered UPnP services
        action_dict = {}
        scdp_dict = {}
        soap_reqs_dict, LAN_reqs_dict, WAN_reqs_dict = {}, {}, {}
        for loc_url, loc_file in discovery_files_dict.iteritems():
            services_dict = self.parseXMLfile(loc_file, loc_url, False)
            all_soap_reqs, LAN_soap_reqs, WAN_soap_reqs = [], [], []
            skip_LAN = True
            skip_WAN = True
            for s_type in services_dict:
                # Build the issues dictionary
                self.issues_dict[loc_url]["ctrl_URL"] = services_dict[s_type][0]
                #self.issues_dict[loc_url]["scdp_URL"] = services_dict[s_type][1]
                # Build the soap requests
                scdp_list = []
                if s_type != 'presentation_upnpbhunter':
                    scdp_list.append(services_dict[s_type][1])
                # Extract the juicy info from SCDP files
                print("[+] Downloading the SCDP file: \"%s\"") % services_dict[s_type][1]
                scdp_dict = self.downloadXMLfiles(scdp_list)
                if not scdp_dict:
                    print("[!] Warning, no UPnP service retrieved for %s" % "".join(scdp_url for scdp_url in scdp_list))
                    continue
                for scdp_file in scdp_dict.values():
                    action_dict = self.parseXMLfile(scdp_file, None, False)
                # Build All the UPnP soap requests
                for ac_name in action_dict:
                    all_soap_reqs.append(self.soapReqBuilder(s_type, services_dict[s_type][0], ac_name, action_dict[ac_name]))    
                # Build only the LAN UPnP soap requests
                if "LANHostConfigManagement" in s_type:
                    skip_LAN = False
                    for ac_name in action_dict:
                        LAN_soap_reqs.append(self.soapReqBuilder(s_type, services_dict[s_type][0], ac_name, action_dict[ac_name]))
                # Build only the WAN UPnP soap requests
                if "WANIPConnection" in s_type or "WANPPPConnection" in s_type:
                    skip_WAN = False
                    for ac_name in action_dict:
                        WAN_soap_reqs.append(self.soapReqBuilder(s_type, services_dict[s_type][0], ac_name, action_dict[ac_name]))
            # Aggregate the built soap requests for each discovered location url
            if not skip_LAN:
                # Only LAN soap requests
                if LAN_soap_reqs:
                    LAN_reqs_dict[loc_url] = LAN_soap_reqs
            if not skip_WAN:
                #  Only WAN soap requests
                if WAN_soap_reqs:
                    WAN_reqs_dict [loc_url] = WAN_soap_reqs
            # All soap requests
            if all_soap_reqs:
                soap_reqs_dict[loc_url] = all_soap_reqs
        return soap_reqs_dict, LAN_reqs_dict, WAN_reqs_dict




    def subscribeReqBuilder(self, subs_URL):
        # Build the subscribe requests for testing purposes
        target_url = urlparse(subs_URL)
        subscribe_ip_port = target_url.netloc
        subscribe_path = target_url.path
        # Callback IP and port must be manually specified on burp repeater
        callback_ip_port = "http://"+"YOUR_LISTENING_IP:YOUR_LISTENING_PORT"
        # Final assemblage of the subscribe request
        subscribe_req = "SUBSCRIBE {0} HTTP/1.1\r\n" \
        "Host: {1}\r\n" \
        "User-Agent: unix/5.1 UPnP/1.1 BHunter/2.0\r\n" \
        "Callback: <{2}>\r\n" \
        "NT: upnp:event\r\n" \
        "Timeout: Second-300\r\n" \
        "\r\n" \
        .format(subscribe_path, subscribe_ip_port, callback_ip_port)
        '''
        EXAMPLE OF BUILT SUBSCRIBE REQUEST:
        -----------------------------------
        SUBSCRIBE /upnp/event/WiFiSetup1 HTTP/1.1
        HOST: 192.168.1.1:49155
        USER-AGENT:  unix/5.1 UPnP/1.1 BHunter/2.0
        CALLBACK: <http://192.168.1.42:4444>
        NT: upnp:event
        TIMEOUT: Second-300
        '''        
        return subscribe_req




    def buildSubscribes(self, discovery_files_dict):
        subs_req_dict = {}
        for loc_url, loc_file in discovery_files_dict.iteritems():
            services_dict = self.parseXMLfile(loc_file, loc_url, False)
            subs_reqs = []
            for s_type in services_dict:
                # Build the issues dictionary
                self.issues_dict[loc_url]["subs_URL"] = services_dict[s_type][2]
                # Build All the UPnP subscribe requests
                if s_type != 'presentation_upnpbhunter':
                    if services_dict[s_type][2]:
                        subs_reqs.append(self.subscribeReqBuilder(services_dict[s_type][2]))
            if subs_reqs:
                subs_req_dict[loc_url] = subs_reqs
        return subs_req_dict




    def presentationReqBuilder(self, pres_URL):
        # Build the presentation requests for testing purposes
        target_url = urlparse(pres_URL)
        presentation_ip_port = target_url.netloc
        presentation_path = target_url.path
        if not presentation_path:
            presentation_path = "/"
        # Final assemblage of the subscribe request
        presentation_req = "GET {0} HTTP/1.1\r\n" \
        "Host: {1}\r\n" \
        "User-Agent: unix/5.1 UPnP/1.1 BHunter/2.0\r\n" \
        "\r\n" \
        .format(presentation_path, presentation_ip_port)
        '''
        EXAMPLE OF BUILT PRESENTATION REQUEST:
        -----------------------------------
        GET /pres_page.html HTTP/1.1
        HOST: 192.168.1.1:49155
        USER-AGENT:  unix/5.1 UPnP/1.1 BHunter/2.0
        '''        
        return presentation_req




    def buildPresentations(self, discovery_files_dict):
        pres_req_dict = {}
        for loc_url, loc_file in discovery_files_dict.iteritems():
            services_dict = self.parseXMLfile(loc_file, loc_url, True)
            pres_reqs = []
            # Build the UPnP presentation request
            if services_dict["presentation_upnpbhunter"]:
                # Build the issues dictionary
                self.issues_dict[loc_url]["pres_URL"] = services_dict["presentation_upnpbhunter"][3]
                pres_reqs.append(self.presentationReqBuilder(services_dict["presentation_upnpbhunter"][3]))
            if pres_reqs:
                pres_req_dict[loc_url] = pres_reqs
        return pres_req_dict




    def getAllSOAPs(self, location_url):
        all_list = []
        if location_url in self.all_SOAPs:
            all_list = self.all_SOAPs[location_url]
        return all_list




    def getLANSOAPs(self, location_url):
        LAN_list = []
        if location_url in self.LAN_SOAPs:
            LAN_list = self.LAN_SOAPs[location_url]
        return LAN_list




    def getWANSOAPs(self, location_url):
        WAN_list = []
        if location_url in self.WAN_SOAPs:
            WAN_list = self.WAN_SOAPs[location_url]
        return WAN_list




    def getSubscribes(self, location_url):
        sub_list = []
        if location_url in self.all_Subs:
            sub_list = self.all_Subs[location_url]
        return sub_list




    def getPresentations(self, location_url):
        pres_list = []
        if location_url in self.all_Pres:
            pres_list = self.all_Pres[location_url]
        return pres_list




    def selectIP(self, e=None):
        # Retrieve the SOAP requests from the selected UPnP service
        selected_ip = self.upnpcombo_targets.getSelectedItem()
        print("[+] Selected IP \"%s\"") % str(selected_ip)




    def selectUPnPService(self, e=None):
        # Retrieve the SOAP requests from the selected UPnP service
        selected_upnp = self.upnpcombo_services.getSelectedItem()
        print("[+] Selected UPnP service at url \"%s\"") % str(selected_upnp)
        # Check if almost an UPnP service was detected
        if not self.getAllSOAPs(selected_upnp) and not self.getSubscribes and not getPresentations:
            self.labelNoneServiceFound.setText("WARNING: no UPnP service was found for this location url")
            return

        # Disable all step three buttons every time the selected UPnP changes
        self.intruderbutton.setEnabled(False)
        self.LANrepeaterbutton.setEnabled(False)
        self.WANrepeaterbutton.setEnabled(False)
        self.Subrepeaterbutton.setEnabled(False)
        self.Presrepeaterbutton.setEnabled(False)

        # Extract the built SOAP requests for the selected UPnP service
        self.all_SOAP_list = list(set(self.getAllSOAPs(selected_upnp)))
        self.LAN_SOAP_list = list(set(self.getLANSOAPs(selected_upnp)))
        self.WAN_SOAP_list = list(set(self.getWANSOAPs(selected_upnp)))
        self.Sub_list = list(set(self.getSubscribes(selected_upnp)))
        self.Pres_list = list(set(self.getPresentations(selected_upnp)))

        # Publish the found UPnP function issues
        self.publishUpnpFunctionIssues()
        
        # Update the plugin UI with the retrieved UPnP profiles to analyze
        if len(self.all_SOAP_list) > 0:
            self.intruderbutton.setEnabled(True)
        self.labelSOAPnum.setText(str(len(self.all_SOAP_list)))
        if len(self.LAN_SOAP_list) > 0:
            self.LANrepeaterbutton.setEnabled(True)
        self.labelLANHOSTnum.setText(str(len(self.LAN_SOAP_list)))
        if len(self.WAN_SOAP_list) > 0:
            self.WANrepeaterbutton.setEnabled(True)
        self.labelWANCONNECTIONnum.setText(str(len(self.WAN_SOAP_list)))
        if len(self.Sub_list) > 0:
            self.Subrepeaterbutton.setEnabled(True)
        self.labelSubnum.setText(str(len(self.Sub_list)))
        if len(self.Pres_list) > 0:
            self.Presrepeaterbutton.setEnabled(True)
        self.labelPresnum.setText(str(len(self.Pres_list)))




    def sendWANUPnPToRepeater(self, e=None):
        # Send the WAN soap requests to the repeater tool
        if self.WAN_SOAP_list:
            #i = 0
            print("[+] Sending to repeater only the WANIP/PPPConnection Soap requests")
            for soap_req in self.WAN_SOAP_list:
                #i += 1
                destination = re.search(r'Host: (.*?)\r\n', soap_req)
                host = destination.group(1).split(":")[0]
                if ":" in destination.group(1):
                    port = destination.group(1).split(":")[1]
                else:
                    port = '80'
                #tab_m = re.search(r'SOAPAction: [^#]*\#(.*?)\"\r\n', soap_req)
                #tab = tab_m.group(1)
                ba_req = bytearray(soap_req, 'utf-8')
                self.callbacks.sendToRepeater(host, int(port), False, ba_req, None)# host+"_"+tab)




    def sendLANUPnPToRepeater(self, e=None):
        # Send the LAN soap requests to the repeater tool
        if self.LAN_SOAP_list:
            print("[+] Sending to repeater only the LANHostConfigManagement Soap requests")
            for soap_req in self.LAN_SOAP_list:
                destination = re.search(r'Host: (.*?)\r\n', soap_req)
                host = destination.group(1).split(":")[0]
                if ":" in destination.group(1):
                    port = destination.group(1).split(":")[1]
                else:
                    port = '80'
                ba_req = bytearray(soap_req, 'utf-8')
                self.callbacks.sendToRepeater(host, int(port), False, ba_req, None)




    def sendUPnPToIntruder(self, e=None):
        # Send the all the soap requests to the intruder tool
        if self.all_SOAP_list:
            print("[+] Sending to intruder all the Soap requests")
            for soap_req in self.all_SOAP_list:
                destination = re.search(r'Host: (.*?)\r\n', soap_req)
                host = destination.group(1).split(":")[0]
                if ":" in destination.group(1):
                    port = destination.group(1).split(":")[1]
                else:
                    port = '80'           
                ba_req = bytearray(soap_req, 'utf-8')
                self.callbacks.sendToIntruder(host, int(port), False, ba_req)




    def sendSubUPnPToRepeater(self, e=None):
        # Send the LAN soap requests to the repeater tool
        if self.Sub_list:
            print("[+] Sending to repeater only the Subscribe requests")
            for sub_req in self.Sub_list:
                destination = re.search(r'Host: (.*?)\r\n', sub_req)
                host = destination.group(1).split(":")[0]
                if ":" in destination.group(1):
                    port = destination.group(1).split(":")[1]
                else:
                    port = '80'
                ba_req = bytearray(sub_req, 'utf-8')
                self.callbacks.sendToRepeater(host, int(port), False, ba_req, None)




    def sendPresUPnPToRepeater(self, e=None):
        # Send the LAN soap requests to the repeater tool
        if self.Pres_list:
            print("[+] Sending to repeater only the Presentation requests")
            for pres_req in self.Pres_list:
                destination = re.search(r'Host: (.*?)\r\n', pres_req)
                host = destination.group(1).split(":")[0]
                if ":" in destination.group(1):
                    port = destination.group(1).split(":")[1]
                else:
                    port = '80'
                ba_req = bytearray(pres_req, 'utf-8')
                self.callbacks.sendToRepeater(host, int(port), False, ba_req, None)




# Class implementing IScanIssue to handle UPnP customized issues
class CustomScanIssue (IScanIssue):
    # Initialize variables
    def __init__(self, httpService, url, issuename, issuedetail, confidence, severity, issuebackground, remediationdetail):
        self._httpService = httpService
        self._url = url
        self._issuename = issuename
        self._issuedetail = issuedetail
        self._severity = severity
        self._confidence = confidence
        self._issuebackground = issuebackground
        self._remediationdetail = remediationdetail

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._issuename

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return self._issuebackground

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._issuedetail

    def getRemediationDetail(self):
        return self._remediationdetail

    def getHttpMessages(self):
        pass

    def getHttpService(self):
        return self._httpService




class CustomIHttpService(IHttpService):
    # Initialize variables
    def __init__(self, protocol, host, port):
        self._protocol = protocol
        self._host = host
        self._port = port

    def getProtocol(self):
        return self._protocol

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

