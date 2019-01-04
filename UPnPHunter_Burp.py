# Upnp BHunter
#
# Simple Burp plugin which could be useful to find active UPnP 
# services/devices running on the specified target IP and extract
# the related SOAP requests.
#
# Copyright (C) 2019   Maurizio Siddu
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



from burp import (IBurpExtender, ITab, IExtensionStateListener)
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




class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    # Define global variables for the burp plugin
    EXTENSION_NAME="UPnP BHunter"
    SSDP_TIMEOUT = 2
    ST_ALL = "ssdp:all"
    ST_ROOTDEV = "upnp:rootdevice"
    PLACEHOLDER = "FUZZ_HERE"
    # Define some other useful global parameters
    target_ip = ""
    all_SOAPs, LAN_SOAPs, WAN_SOAPs = {}, {}, {}
    all_SOAP_list, LAN_SOAP_list, WAN_SOAP_list = [], [], []
    STOP_THREAD = False


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
        self.textfield_step1 = JTextField("", 20)
        self.labeltitle_step1 = JLabel("[1st STEP] Discover UPnP Locations")
        self.labeltitle_step1.setFont(Font('Tahoma', Font.BOLD, 14))
        self.labeltitle_step2 = JLabel("[2nd STEP] Select an UPnP Service")
        self.labeltitle_step2.setFont(Font('Tahoma', Font.BOLD, 14))
        self.labeltitle_step3 = JLabel("[3rd STEP] Time to Attack it")
        self.labeltitle_step3.setFont(Font('Tahoma', Font.BOLD, 14))
        self.labelsubtitle_step1 = JLabel("Specify the IPv4 in scope and start UPnP discovery")
        self.labelsubtitle_step2 = JLabel("Select which of the found UPnP services will be probed")
        self.labelsubtitle_step3 = JLabel("Select how to test the extracted UPnP SOAP requests")
        self.label_step1 = JLabel("Target IP")
        self.label_step2 = JLabel("Found UPnp Services")
        self.label_step3 = JLabel("Send all the extracted SOAP requests     ")
        self.labelerror_step1 = JLabel(" ")
        self.labelerror_step1.setFont(Font('Tahoma', Font.BOLD, 12))
        self.labelerror_step1.setForeground(Color.red)
        self.labelstatus = JLabel("             Status")
        self.labelempty_step1 = JLabel("                ")
        self.labelempty_step2 = JLabel("  ")
        self.labelupnp = JLabel("UPnP list")
        self.labelLANHOST = JLabel("Send the interesting LANHostConfigManagement SOAP requests     ")
        self.labelWANCONNECTION = JLabel("Send the interesting WANIP/PPPConnection SOAP requests     ")
        self.labelSOAPnum = JLabel("0")
        self.labelLANHOSTnum = JLabel("0")
        self.labelWANCONNECTIONnum = JLabel("0")

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
        self.confirmbutton.setEnabled(False)
        self.intruderbutton.setEnabled(False)
        self.LANrepeaterbutton.setEnabled(False)
        self.WANrepeaterbutton.setEnabled(False)

        # Create the combo box, select item at index 0 (first item in list)
        self.upnpservices = ["       "]
        self.upnpcombo = JComboBox(self.upnpservices)
        self.upnpcombo.setSelectedIndex(0)
        self.upnpcombo.setEnabled(False)

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
        self.targetpanel_step1.add(self.textfield_step1)
        self.targetpanel_step1.add(self.startbutton)
        self.targetpanel_step1.add(self.clearbutton)
        self.targetpanel_step1.add(self.labelstatus)
        self.targetpanel_step1.add(self.progressbar)
        self.errorpanel_step1 = JPanel()
        self.errorpanel_step1.setLayout(BorderLayout())
        self.errorpanel_step1.add(self.labelempty_step1,BorderLayout.WEST)
        self.errorpanel_step1.add(self.labelerror_step1)

        # Assembling first step panel components
        self.panel_step1.add(self.titlepanel_step1,BorderLayout.NORTH)
        self.panel_step1.add(self.targetpanel_step1,BorderLayout.WEST)
        self.panel_step1.add(self.errorpanel_step1,BorderLayout.SOUTH)
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
        self.selectpanel_step2.add(self.labelupnp)
        self.selectpanel_step2.add(self.upnpcombo)
        self.selectpanel_step2.add(self.confirmbutton)
        self.errorpanel_step2 = JPanel()
        self.errorpanel_step2.setLayout(BorderLayout())
        self.errorpanel_step2.add(self.labelempty_step2,BorderLayout.WEST)

        # Assembling second step panel components
        self.panel_step2.add(self.titlepanel_step2,BorderLayout.NORTH)
        self.panel_step2.add(self.selectpanel_step2,BorderLayout.WEST)
        self.panel_step2.add(self.errorpanel_step2,BorderLayout.SOUTH)
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
        secondcolumn = underlayout.createParallelGroup()
        secondcolumn.addComponent(self.labelSOAPnum)
        secondcolumn.addComponent(self.labelLANHOSTnum)
        secondcolumn.addComponent(self.labelWANCONNECTIONnum)
        thirdcolumn = underlayout.createParallelGroup()
        thirdcolumn.addComponent(self.intruderbutton)
        thirdcolumn.addComponent(self.LANrepeaterbutton)
        thirdcolumn.addComponent(self.WANrepeaterbutton)
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
        top2bottom.addGroup(firstrow)
        top2bottom.addGroup(secondrow)
        top2bottom.addGroup(thirdrow)
        underlayout.setHorizontalGroup(left2right)
        underlayout.setVerticalGroup(top2bottom)

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
        layout.setVerticalGroup(
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
        if self.upnpcombo.isEnabled():
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
        self.target_ip = ""
        self.all_SOAPs, self.LAN_SOAPs, self.WAN_SOAPs = {}, {}, {}
        self.all_SOAP_list, self.LAN_SOAP_list, self.WAN_SOAP_list = [], [], []
        self.textfield_step1.setText("")
        self.labelerror_step1.setText(" ")
        self.progressbar.setString("Ready")
        self.progressbar.setValue(0)
        self.upnpcombo.removeAllItems()
        self.upnpcombo.setEnabled(False)
        self.confirmbutton.setEnabled(False)
        self.intruderbutton.setEnabled(False)
        self.labelSOAPnum.setText("0")
        self.LANrepeaterbutton.setEnabled(False)
        self.labelLANHOSTnum.setText("0")
        self.WANrepeaterbutton.setEnabled(False)
        self.labelWANCONNECTIONnum.setText("0")
        print("[+] Clearing all data")
        return


    def startHunting(self, e=None):
        # Starting the UPnP hunt
        def startHunting_run():
            # Initialize the internal parameters every time the start-discovery button is clicked
            self.all_SOAPs, self.LAN_SOAPs, self.WAN_SOAPs = {}, {}, {}
            self.all_SOAP_list, self.LAN_SOAP_list, self.WAN_SOAP_list = [], [], []
            found_loc = []
            self.target_ip = self.textfield_step1.getText()
            if not (re.match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', self.target_ip)):
                # Invalid IPv4 address, the hunt is aborted 
                print("[E] The specified target IPv4 address is not valid")
                self.labelerror_step1.setText("ERROR, INVALID IPv4 ADDRESS !!!")
                return
            else:
                # Valid IPv4 address, so hunt could begin
                print("[+] Selected IP \"%s\"") % self.target_ip
                self.labelerror_step1.setText(" ")
                self.progressbar.setString("Running...")
                self.progressbar.setValue(20)
                found_loc = self.discoverUpnpLocations()
                self.progressbar.setValue(40)
                #scope_urls = self.checkIPScope(found_loc)
                discovery_files = self.downloadXMLfiles(self.checkIPScope(found_loc))
                self.progressbar.setValue(60)
                self.all_SOAPs,self.LAN_SOAPs,self.WAN_SOAPs = self.buildSOAPs(discovery_files)
                # Update the checkbox list in the plugin UI with the discovery results
                self.progressbar.setValue(80)
                self.progressbar.setString("Done")
                self.progressbar.setValue(100)
                self.upnpcombo.setEnabled(True)
                self.updateCheckboxList(found_loc)
                if self.STOP_THREAD:
                    return

        # Start a background thread to run the above nested function in order to prevent the blocking of plugin UI
        self.th = threading.Thread(target=startHunting_run)
        #self.th.daemon = True    # This does not seem to be useful
        self.th.setName("th-BHunter")
        self.th.start()


    def ssdpReqBuilder(self, ssdp_timeout, st_type):
        # Builder of the two ssdp msearch request types
        msearch_req = "M-SEARCH * HTTP/1.1\r\n" \
        "HOST: 239.255.255.250:1900\r\n" \
        "MAN: \"ssdp:discover\"\r\n" \
        "MX: {0}\r\n" \
        "ST: {1}\r\n" \
        "\r\n" \
        .format(ssdp_timeout, st_type)
        return msearch_req


    def sendMsearch(self, ssdp_req):
        # Send the ssdp request
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        buf_resp = []
        resp = ""
        while len(ssdp_req):
            # Blocking socket client until the request is completely sent
            try:
                sent = sock.sendto(ssdp_req.encode("ASCII"), ("239.255.255.250", 1900))
                ssdp_req = ssdp_req[sent:]
            except socket.error, exc:
                if exc.errno != errno.EAGAIN:
                    print("[E] Got error %s with socket when sending") % exc
                    sock.close()
                    raise exc
                print("[!] Blocking socket until ", len(ssdp_req), " is sent")       
                select.select([], [sock], [])
                continue
        # Blocking socket until there are ssdp responses to be read or timeout is reached
        readable, __, __ = select.select([sock], [], [], self.SSDP_TIMEOUT)
        if not readable:
            # Timeout reached without receiving any ssdp response
            print("[!] Got timeout without receiving any ssdp response")
        else:
            # Almost an ssdp response was received
            if readable[0]:
                try:
                    data = sock.recv(1024)
                    if data:
                        buf_resp.append(data.decode("ASCII"))
                except socket.error, exc:
                    print("[E] Got error %s with socket when receiving") % exc
                    sock.close()
                    raise exc
        # Assemblage of the ssdp response from received data chunks 
        resp = "".join(buf_resp)
        sock.close()
        return resp


    def discoverUpnpLocations(self):
        # Retrieve a list of UPnP location-urls via ssdp M-SEARCH broadcast request
        locations = set()
        location_regex = re.compile("location:[ ]*(.+)\r\n", re.IGNORECASE)    
        # Use two possible type of ssdp requests 
        ssdp_requests = [self.ssdpReqBuilder(self.SSDP_TIMEOUT, self.ST_ALL), self.ssdpReqBuilder(self.SSDP_TIMEOUT, self.ST_ROOTDEV)]
        # First try with "Ssdp:All" request type
        print("[+] Start hunting with \"Ssdp:All\" ssdp request type")
        ssdp_response = self.sendMsearch(ssdp_requests[0])
        # Then try with the alternative "Root:Device" request type
        if not ssdp_response:
            print("[+] Retrying with \"Root:Device\" ssdp request type")
            ssdp_response = self.sendMsearch(ssdp_requests[1])
        # Extract location heaader information from ssdp response
        if ssdp_response:
            location_result = location_regex.search(ssdp_response.decode("ASCII"))
            if location_result and (location_result.group(1) in locations) == False:
                locations.add(location_result.group(1))
        else:
            print("[!] Unsucessfull hunt, none active UPnP service was found. Try with other target IPs")
        upnp_locations = list(locations)
        return upnp_locations


    def checkIPScope(self, found_locations):
        # Create whitelist of in scope IPs and then check if found locations are in scope
        scope_urls = []
        # Check if the found location IPs are in target scope
        if len(found_locations) > 0:
            for fl_url in found_locations:
                fl_ip = urlparse(fl_url).netloc
                if fl_ip.split(":")[0] == self.target_ip:
                    scope_urls.append(fl_url)
                    print("[+] Found valid location URL \"%s\" in scope") % fl_url
                else:
                    print("[!] Discarded location URL \"%s\" because out of scope") % fl_url
        return scope_urls


    def updateCheckboxList(self, cb_list):
        # Update the combobox items after location urls have been found
        def updateCheckboxList_run(cb_list):
            scope_list = []
            self.upnpcombo.removeAllItems()
            # First check if any UPnP service was found
            if not cb_list:
                self.upnpcombo.addItem("None UPnP service found")
                return
            # Then check if any of the found UPnP services is in scope 
            scope_list = self.checkIPScope(cb_list)
            if not scope_list:
                self.upnpcombo.addItem("None UPnP service in the specified scope")
                return
            # Insert only the found location urls that are in scope
            for scope_url in scope_list:
                self.upnpcombo.addItem(scope_url)
            self.confirmbutton.setEnabled(True)
            self.upnpcombo.setSelectedIndex(0)
        # Call the runnable method to update the plugin UI with results
        SwingUtilities.invokeLater(PyRunnable(updateCheckboxList_run, cb_list))


    def downloadXMLfiles(self, download_urls):
        # Download the specified xml files
        xml_files_dict = {}
        is_https = True
        # First check if list of location urls is empty
        if download_urls:
            for d_url in download_urls:
                # Extract the various location url items
                d_url_parsed = urlparse(d_url)
                if d_url_parsed.scheme == "http":
                    is_https = False
                d_netloc = d_url_parsed.netloc
                d_host = d_netloc.split(":")[0]
                if not ":" in d_netloc:
                    d_port = "80"
                else:
                    d_port = d_netloc.split(":")[1]
                # Build the http download requests using Burp functions
                ba_download_req = self.helpers.buildHttpRequest(URL(d_url_parsed.scheme, d_host, int(d_port), d_url_parsed.path))
                ba_download_resp = self.callbacks.makeHttpRequest(d_host, int(d_port), is_https, ba_download_req)
                download_resp = "".join(map(chr, ba_download_resp))
                if download_resp:
                    print("[+] Successfully downloaded xml file \"%s\" ") % d_url
                    # Extract the response body
                    splitted_resp = download_resp.split("\r\n\r\n")
                    if len(splitted_resp) > 1:
                        xml_files_dict[d_url] = splitted_resp[1]
                else:
                    print("[!] Skipping, failed to retrieve the XML file from: %s ") % d_url
        return xml_files_dict


    def parseXMLfile(self, file_content, location_url):
        # Extract the juicy info from UPnP Description and SCDP xml files
        # Parsing with regexp (yes I known, an xml-parser could be used)
        output_dict = {}
        service_list = []
        action_list = []
        arg_list = []
        # First remove newlines and whitelines from the xml file
        file2parse = re.sub(r"[\r\n\s\t]*","", file_content)
        # Check if is a Description (with location_url) or SCDP file
        if location_url:
            # Parse the Description XML file to extract the info about Services
            base_URL_elem = re.search("<base_URL>(.*?)</base_URL>", file2parse)
            # Retrieve the baseURL item
            if base_URL_elem:
                base_URL = base_URL_elem.groups()[0].rstrip('/')
            else:
                url = urlparse(location_url)
                base_URL = '%s://%s' % (url.scheme, url.netloc)
            service_list = re.findall("<service>(.*?)</service>", file2parse)
            # Retrieve serviceType, controlURL and SCDPURL values
            for serv in service_list:
                service_type = re.search("<serviceType>(.*?)</serviceType>", serv).groups()[0]
                ctrl_URL = base_URL + re.search("<controlURL>(.*?)</controlURL>", serv).groups()[0]
                scpd_URL = base_URL + re.search("<SCPDURL>(.*?)</SCPDURL>", serv).groups()[0]
                # Aggregate the extracted info 
                output_dict[service_type] = [ctrl_URL, scpd_URL]
        else:
            # Parse the SCDP xml file to extract the info about Actions
            action_list = re.findall("(<action>.*?)</action>", file2parse)
            # Retrieve action-name and if present the argument-name values
            for act in action_list:
                act_name = re.search("<action><name>(.*?)</name>", act).groups()[0]
                arg_name = []
                # Determine if is a Get-action or not
                if act_name.startswith("Get"):
                    # Get-action found
                    arg_direction = re.search("<argument><name>(.*?)</name><direction>(.*?)</direction>", act)
                    if arg_direction and "in" in arg_direction.groups()[1]:
                        # Get-action with input arguments
                        arg_name.append(str(arg_direction.groups()[0]))
                    else:
                        # Get-action without input arguments
                        arg_name.append("")
                else:
                    # Not Get-action
                    arg_exists = re.search("<argument><name>(.*?)</name>", act)
                    if arg_exists:
                        arg_list = re.findall("<argument><name>(.*?)</name>", act)
                        for arg in arg_list:
                            arg_name.append(arg)
                    else:
                        # Not Get-action without any argument
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
        sfuzz = []
        for arg_name in arg_list:
            if arg_name:
                sfuzz.append("        <{0}>{1}</{0}>".format(arg_name, self.PLACEHOLDER))
            else:
                # In case of Get-action or an actionwithout arguments
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
        soap_reqs_dict, LAN_reqs_dict, WAN_reqs_dict = {}, {}, {}
        for loc_url, loc_file in discovery_files_dict.iteritems():
            services_dict = self.parseXMLfile(loc_file, loc_url)
            all_soap_reqs, LAN_soap_reqs, WAN_soap_reqs = [], [], []
            skip_LAN = True
            skip_WAN = True
            for s_type in services_dict:
                scdp_list = []
                scdp_list.append(services_dict[s_type][1])
                # Extract the juicy info from SCDP files
                print("[+] Downloading the SCDP file: \"%s\"") % services_dict[s_type][1]
                scdp_dict = self.downloadXMLfiles(scdp_list)
                for scdp_file in scdp_dict.values():
                    action_dict = self.parseXMLfile(scdp_file, None)
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
                LAN_reqs_dict[loc_url] = LAN_soap_reqs
            if not skip_WAN:
                #  Only WAN soap requests
                WAN_reqs_dict[loc_url] = WAN_soap_reqs
            # All soap requests
            soap_reqs_dict[loc_url] = all_soap_reqs
        return soap_reqs_dict, LAN_reqs_dict, WAN_reqs_dict


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


    def selectUPnPService(self, e=None):
        # Retrieve the SOAP requests from the selected UPnP service
        selected_upnp = self.upnpcombo.getSelectedItem()
        print("[+] Selected UPnP service at url \"%s\"") % str(selected_upnp)
        
        # Extract the built SOAP requests for the selected UPnP service
        self.all_SOAP_list = list(set(self.getAllSOAPs(selected_upnp)))
        self.LAN_SOAP_list = list(set(self.getLANSOAPs(selected_upnp)))
        self.WAN_SOAP_list = list(set(self.getWANSOAPs(selected_upnp)))
        
        # Update the plugin UI with the retrieved UPnP profiles to analyze
        if self.all_SOAP_list:
            self.intruderbutton.setEnabled(True)
            self.labelSOAPnum.setText(str(len(self.all_SOAP_list)))
        if self.LAN_SOAP_list:
            self.LANrepeaterbutton.setEnabled(True)
            self.labelLANHOSTnum.setText(str(len(self.LAN_SOAP_list)))
        if self.WAN_SOAP_list:
            self.WANrepeaterbutton.setEnabled(True)
            self.labelWANCONNECTIONnum.setText(str(len(self.WAN_SOAP_list)))


    def sendWANUPnPToRepeater(self, e=None):
        # Send the WAN soap requests to the repeater tool
        if self.WAN_SOAP_list:
            print("[+] Sending to repeater only the WANIP/PPPConnection Soap requests")
            for soap_req in self.WAN_SOAP_list:
                destination = re.search(r'Host: (.*?)\n', soap_req)
                host = destination.group(1).split(":")[0]
                if ":" in destination.group(1):
                    port = destination.group(1).split(":")[1]
                else:
                    port = '80'
                ba_req = bytearray(soap_req)
                self.callbacks.sendToRepeater(host, int(port), False, ba_req, None)


    def sendLANUPnPToRepeater(self, e=None):
        # Send the LAN soap requests to the repeater tool
        if self.LAN_SOAP_list:
            print("[+] Sending to repeater only the LANHostConfigManagement Soap requests")
            for soap_req in self.LAN_SOAP_list:
                destination = re.search(r'Host: (.*?)\n', soap_req)
                host = destination.group(1).split(":")[0]
                if ":" in destination.group(1):
                    port = destination.group(1).split(":")[1]
                else:
                    port = '80'
                ba_req = bytearray(soap_req)
                self.callbacks.sendToRepeater(host, int(port), False, ba_req, None)


    def sendUPnPToIntruder(self, e=None):
        # Send the all the soap requests to the intruder tool
        if self.all_SOAP_list:
            print("[+] Sending to intruder all the Soap requests")
            for soap_req in self.all_SOAP_list:
                destination = re.search(r'Host: (.*?)\n', soap_req)
                host = destination.group(1).split(":")[0]
                if ":" in destination.group(1):
                    port = destination.group(1).split(":")[1]
                else:
                    port = '80'           
                ba_req = bytearray(soap_req)
                self.callbacks.sendToIntruder(host, int(port), False, ba_req)
