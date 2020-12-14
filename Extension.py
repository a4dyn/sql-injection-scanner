# -*- coding: utf-8 -*-

'''
A Burp Extension for finding simple SQL exploitable. Supports GET and POST with key-value of urlencoded, Json and XML data types


* Created by Junhan Duan on August 25th, 2020
* First version completed on Spetember 10th, 2020
'''

# Burp
from burp import ITab
from burp import IHttpListener
from burp import IBurpExtender
from burp import IMessageEditorTab
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from burp import IMessageEditorController
from burp import IMessageEditorTabFactory

# Java
from java import awt
from javax import swing
from java.awt import Font
from java.awt import Color
from java.awt import Dimension
from java.awt import BorderLayout
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter
from javax.swing import JTable
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JComboBox
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import SwingUtilities
from javax.swing.table import TableRowSorter
from javax.swing.table import DefaultTableModel
from javax.swing.table import AbstractTableModel
from javax.swing.event import TableModelListener
from javax.swing.event import ListSelectionListener

# Python
import re
import os
import sys
import copy
import time
import json
from threading import Lock
from threading import Timer
from threading import Thread

# Python (XML)
'''
Using xml.sax to parse untrusted XML data is known to be vulnerable to XML attacks
However, since jython does not have defusedxml package, this problem cannot be solved by simply importing defusedxml package
'''
import xml.sax
import xml.sax.handler
from xml.etree.ElementTree import Element
from xml.etree.ElementTree import tostring

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener, IMessageEditorController, IHttpListener):

    '''
    IBurpExtender:               Hook into burp and inherit base classes
    ITab:                        Create new tabs inside burp
    IMessageEditorTabFactory:    Access createNewInstance
    '''
    def registerExtenderCallbacks(self, callbacks):

        # Set encoding to utf-8 to avoid some errors
        reload(sys)
        sys.setdefaultencoding('utf8')

        # Keep a reference to callback object and helper object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Set the extension name that shows in the burp extension menu
        callbacks.setExtensionName("InjectionScanner")

        # Create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._logLock = Lock()
        self._httpLock = Lock()

        # The length of the basis used to fetch abnormal data, default to zero
        self._basisLen = 0

        # 1: {POST. GET}; 2: {urlencoded, json, xml}
        self._postGet = 'NaN'
        self._dataType = 'NaN'

        # Scan list
        self._simpleList = ['\'', '\"', '/', '/*', '#', ')', '(', ')\'', '(\'', 'and 1=1', 'and 1=2', 'and 1>2', 'and 12', '+', 'and+12', '/**/and/**/1']
        self._xmlList = ['a', 'b', 'c', 'd', 'e']   # Not setted

        # Response mutex: True = is blocking; False = free to go
        # self._mutexR = False

        # Other classes instance
        self._dataTable = Guis_DefaultTM()
        self._logTable = Guis_AbstractTM(self)
        self._xh = XMLHandler()
        listeners = Guis_Listeners(self, self._logTable)

        '''
        Setting GUIs
        '''
        # Divide the whole pane two: one upper and one lower pane
        self._mainSplitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._mainSplitpane.setResizeWeight(0.4)

        # Initizlize request table
        dataTable = JTable(self._dataTable)
        dataScrollPane = JScrollPane(dataTable)
        dataScrollPane.setPreferredSize(Dimension(0, 125))
        self._dataTable.addTableModelListener(listeners)

        # Initialize log table
        logTable = Guis_LogTable(self._logTable)
        logScrollPane = JScrollPane(logTable)
        logScrollPane.setPreferredSize(Dimension(0, 125))

        # Split the upper pane to two panes
        tableSplitpane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        tableSplitpane.setResizeWeight(0.5)

        # Set the data table to the left and log to the right
        tableSplitpane.setLeftComponent(dataScrollPane)
        tableSplitpane.setRightComponent(logScrollPane)

        # Tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())

        # Create buttons that do operation with the test
        self._basisLabel = JLabel('Basis: ' + str(self._basisLen))
        self._levelLabel = JLabel('Level:')
        self._setBasisButton = JButton('Set Basis')
        self._hitOnceButton = JButton('Hit Once')
        self._autoScanButton = JButton('Auto Scan')
        self._clearLogButton = JButton('Clear Log')
        self._cancelButton = JButton('Cancel')
        self._levelSelection = JComboBox()

        self._levelSelection.addItem('1')
        self._levelSelection.addItem('2')
        self._levelSelection.addItem('3')
        self._hitOnceButton.addActionListener(listeners)
        self._autoScanButton.addActionListener(listeners)
        self._clearLogButton.addActionListener(listeners)
        self._setBasisButton.addActionListener(listeners)
        self._cancelButton.addActionListener(listeners)
        self._basisLabel.setPreferredSize(Dimension(100, 20))

        # Create bottom pane for holding the buttons
        buttonPane = JPanel()
        buttonPane.setLayout(BorderLayout())
        centerPane = JPanel()
        leftPane = JPanel()
        rightPane = JPanel()
        leftPane.add(self._basisLabel)
        centerPane.add(self._setBasisButton)
        centerPane.add(self._hitOnceButton)
        centerPane.add(self._autoScanButton)
        centerPane.add(self._cancelButton)
        centerPane.add(self._clearLogButton)
        rightPane.add(self._levelLabel)
        rightPane.add(self._levelSelection)
        buttonPane.add(centerPane, BorderLayout.CENTER)
        buttonPane.add(leftPane, BorderLayout.WEST)
        buttonPane.add(rightPane, BorderLayout.EAST)

        # Create and set the bottom panel that holds viewers and buttons
        utilPane = JPanel()
        utilPane.setLayout(BorderLayout())
        utilPane.add(tabs, BorderLayout.CENTER)
        utilPane.add(buttonPane, BorderLayout.SOUTH)

        self._mainSplitpane.setLeftComponent(tableSplitpane)
        self._mainSplitpane.setRightComponent(utilPane)

        # Customize UI components
        callbacks.customizeUiComponent(self._mainSplitpane)
        callbacks.customizeUiComponent(dataTable)
        callbacks.customizeUiComponent(dataScrollPane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(logScrollPane)
        callbacks.customizeUiComponent(tabs)
        callbacks.customizeUiComponent(buttonPane)
        callbacks.customizeUiComponent(utilPane)
        callbacks.customizeUiComponent(self._basisLabel)
        callbacks.customizeUiComponent(self._setBasisButton)
        callbacks.customizeUiComponent(self._hitOnceButton)
        callbacks.customizeUiComponent(self._autoScanButton)
        callbacks.customizeUiComponent(self._clearLogButton)
        callbacks.customizeUiComponent(self._levelSelection)
        callbacks.customizeUiComponent(self._cancelButton)

        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)

        # Register the context menu and message editor for new tabs
        callbacks.registerContextMenuFactory(self)

        # Register as a HTTP listener
        callbacks.registerHttpListener(self)

        return

    '''
    ITab implementation
    '''
    def getTabCaption(self):
        return 'InjectionScanner'

    def getUiComponent(self):
        return self._mainSplitpane

    '''
    IContextMenuFactory implementation
    '''
    def createMenuItems(self, invocation):
        menu = []

        # Which part of the interface the user selects
        ctx = invocation.getInvocationContext()

        # Message viewer request will show menu item if selected by the user
        if ctx == 0 or ctx == 2:
          menu.append(swing.JMenuItem("Send to InjectionScanner", None, actionPerformed=lambda x, inv=invocation: self.sendToExtender(inv)))

        return menu if menu else None

    '''
    IMessageEditorController Implementation
    '''
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()


    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()


    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

    '''
    IHttpListener implementation
    '''   
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        # Skip this function if the message is request
        if messageIsRequest:
            return

        # Lock the log entry in case race condition
        self._logLock.acquire()
        row = self._log.size()

        # Fetch request message
        requestBody = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeResponse(requestBody)
        requestHeaders = requestInfo.getHeaders()
        if self._postGet == 'POST':
            requestData = self._helpers.bytesToString(requestBody[requestInfo.getBodyOffset():])
        elif self._postGet == 'GET':
            for header in requestHeaders:

                if 'GET' in header:
                    # If the request is GET, update the GET data
                    requestUrl = re.sub('^GET\s+', '', header, re.IGNORECASE)
                    requestUrl = re.sub('\sHTTP/1.1\S*', '', requestUrl, re.IGNORECASE)

                    if '?' in requestUrl:
                        requestData = re.sub('\S*\?', '', requestUrl, re.IGNORECASE)

                    else:
                        print('processHttpMessage: no parameter in GET url')
        else:
            print('processHttpMessage: _postGet not defined')
            self._logLock.release()
            return
        
        # Fetch the http type (GET/POST)
        httpType = requestHeaders[0].split(' ')

        # Fetch response message
        responseBody = messageInfo.getResponse()
        responseInfo = self._helpers.analyzeResponse(responseBody)
        responseHeaders = responseInfo.getHeaders()
        self._responseLength = ''

        # Fetch the content length
        self._responseLength = self.fetchContentLength(responseHeaders)

        # If the response message is auto-generated, ignore it. If not, add it into the log list
        if self._callbacks.getToolName(toolFlag) != 'Proxy':

            self._log.add(LogEntry(httpType[0], requestData, self._callbacks.saveBuffersToTempFiles(messageInfo) , self._responseLength))
            self._logTable.fireTableRowsInserted(row, row)

        self._logLock.release()


    '''
    Fetch content length from the headers given
    '''
    def fetchContentLength(self, fromHeaders):

        for header in fromHeaders:
            if re.search('^Content-Length', header, re.IGNORECASE) is not None:
                return re.sub('^Content-Length\:\s+', '', header, re.IGNORECASE)

    '''
    When the user select 'Send to InjectionScanner', call this function
    '''
    def sendToExtender(self, invocation):

        # Init/reset request data before sending to extender
        self.initRequestInfo()

        try:
            # Initialize basic information
            invMessage = invocation.getSelectedMessages()
            requestMessage = invMessage[0]
            requestInfo = self._helpers.analyzeRequest(requestMessage)
            self._requestBody = requestMessage.getRequest()

            # Set the _currentlyDisplayedItem so each time the data is sent to the extender
            self._currentlyDisplayedItem = self._callbacks.saveBuffersToTempFiles(requestMessage)

            # Fetch the request data
            bodyLen = len(self._helpers.bytesToString(self._requestBody))
            if requestInfo.getBodyOffset() < bodyLen:
                self._requestData = self._helpers.bytesToString(self._requestBody[requestInfo.getBodyOffset():])
            elif requestInfo.getBodyOffset() == bodyLen:
                self._requestData = ''
            else:
                print('sendToExtender: body length < body offset')

            # Fetch the headers and Http service
            requestHeaders = list(requestInfo.getHeaders())
            self._httpService = requestMessage.getHttpService()

            # Initialize POST/GET identifier and User-Agent
            for header in requestHeaders:
                if re.search('^POST', header, re.IGNORECASE) is not None:
                    self._postGet = 'POST'

                elif re.search('^GET', header, re.IGNORECASE) is not None:
                    self._postGet = 'GET'

                    # If the request is GET, initialize the url and GET data
                    self._requestUrl = re.sub('^GET\s+', '', header, re.IGNORECASE)
                    self._requestUrl = re.sub('\sHTTP/1.1\S*', '', self._requestUrl, re.IGNORECASE)

                    if '?' in self._requestUrl:
                        self._requestDataGet = re.sub('\S*\?', '', self._requestUrl, re.IGNORECASE)

                    else:
                        print('sendToExtender: no parameter in GET url')

                # If the request if POST, fetch the request data type by content type
                if self._postGet == 'POST' and re.search('^Content-Type', header, re.IGNORECASE) is not None:

                    contentType = re.sub('^Content-Type', '', header, re.IGNORECASE)
                    if 'urlencoded' in contentType:
                           self._dataType = 'urlencoded'

                    elif 'json' in contentType:
                           self._dataType = 'json'

                    elif 'xml' in contentType or 'http' in conentType:
                        self._dataType = 'xml'

                    else:
                        print('sendToExtender: _dataType is not supported, do not scan')
                
                # Initialze the User-Agent if it exists
                if re.search('^User-Agent', header, re.IGNORECASE) is not None:
                    self._userAgent = re.sub('^User-Agent\:\s+', '', header, re.IGNORECASE)

            # If there's no content type in the header,fetch from data
            if self._postGet == 'POST' and self._dataType == '':

                if self._requestData != '':

                    if self._requestData[0] == '{' and '}' in self._requestData and ':' in self._requestData:
                        self._dataType = 'json'

                    elif self._requestData[0] == '<' and self._requestData[-1] == '>':
                        self._dataType = 'xml'

                    else:
                        self._dataType = 'urlencoded'

                else:
                       print('sendToExtender: _postGet is POST but _requestData is null')

            # Clear the table before adding elements
            self._dataTable.setRowCount(0)

            # Update request viewer
            self.updateRequestViewer()

            # Fill request data
            self.fillRequestData()

        except Exception as e: print(e)

    '''
    Fill the data into the request table
    '''
    def fillRequestData(self):

        # If _postGet is GET, also adds URL to the table
        if self._postGet == 'GET':

            dataList = self._requestDataGet.split('&')
            for data in dataList:

                if '=' in data:
                    x = data.split('=', 1)
                    self._dataDict[str(x[0])] = str(x[1])
                    self._dataTable.addRow([str(x[0]), str(x[1])])
                    self._dataLen += 1

            self._dataTable.addRow(['URL', self._requestUrl])
            self._UrlRow = self._dataLen

            if self._userAgent != '':
                self._dataTable.addRow(['User-Agent', self._userAgent])

        elif self._postGet == 'POST':

            if self._dataType == 'urlencoded':

                dataList = self._requestData.split('&')
                for data in dataList:

                    if '=' in data:
                        x = data.split('=', 1)
                        self._dataDict[str(x[0])] = str(x[1])
                        self._dataTable.addRow([str(x[0]), str(x[1])])
                        self._dataLen += 1

            elif self._dataType == 'json':

                self._dataDict = json.loads(self._requestData)
                for key in self._dataDict:

                    # Convert '"' to '\"' to be the same as that in the data
                    value = str(self._dataDict[key])
                    if '\"' in value:
                        value = value.replace('\"', '\\\"')
                    self._dataDict[key] = value

                    self._dataTable.addRow([str(key), self._dataDict[key]])
                    self._dataLen += 1

            elif self._dataType == 'xml':

                # Use xml package to convert the xml string to dict
                # Note1: the xml dict will be in reverse order
                # Note2: the arrtibute will also be added into dict, need to be pop
                # Note3: special characters like \" will be considered as "
                xml.sax.parseString(self._requestData, self._xh)
                self._attr = re.sub('\>(\S*\s*)*', '', self._requestData[1:], re.IGNORECASE)

                self._dataDict = self._xh.getDict()
                self._dataDict.pop(self._attr)

                for key in self._dataDict:
                    self._dataTable.addRow([str(key), str(self._dataDict[key])])
                    self._dataLen += 1

            else:
                print('fillRequestData: _dataType not defined')

            if self._userAgent != '':
                self._dataTable.addRow(['User-Agent', self._userAgent])
                self._savedUserAgent = self._userAgent

        else:
            print('fillRequestData: _postGet not defined')

    '''
    Receive & update the response after sending request to the server
    '''
    def receiveResponse(self):

        # Init/reset response data before receiving response
        self.initResponseInfo()

        # Launch the http thread
        self._httpThread = Thread(target = self.makeRequest, args = (self._httpService, self._requestBody, ))
        self._httpThread.start()

    '''
    Make Http request to a service
    '''
    def makeRequest(self, httpService, requestBody):
        self._httpLock.acquire()

        # Disable the hit buttons before starting the thread
        self._hitOnceButton.setEnabled(False)
        self._autoScanButton.setEnabled(False)

        self._responseMessage = self._callbacks.makeHttpRequest(httpService, requestBody)

        # Enable the hit buttons
        self._hitOnceButton.setEnabled(True)
        self._autoScanButton.setEnabled(True)

        # Unblock the mutex
        self._httpLock.release()

    '''
    updateRequestViewer
    '''
    def updateRequestViewer(self):
        self._requestViewer.setMessage(self.getRequest(), True)

    '''
    updateResponseViewer
    '''
    def updateResponseViewer(self):
        self._responseViewer.setMessage(self.getResponse(), False)

    '''
    Level 1 auto: only loop through the data, do not modify the 'submit' section
    '''
    def autoScan1(self):
        # TODO: Add a 'cancel' button to stop when the user think it takes too long
        # TODO: Add XML support
        if self._postGet == 'GET':

            for i in range(0, self._dataLen):

                title = self._dataTable.getValueAt(i, 0) 
                baseValue = self._dataDict[title]

                for value in self._simpleList:

                    # TODO: update more value that should not be changed
                    if 'submit' not in title.lower() and 'submit' not in self._dataDict[title].lower() and 'search' not in title.lower() and 'search' not in self._dataDict[title].lower():
                        
                        # Update the table in case the loop interrupt in the middle
                        # Note that the URL will be automatically updated due to this code, so no need to manually update the URL section
                        self._dataTable.setValueAt(value, i, 1)

                        # Send & request the HTTP request/response
                        self.updateRequestViewer()
                        self.receiveResponse()
                
                # Reset the table
                self._dataTable.setValueAt(baseValue, i, 1)


        if self._postGet == 'POST':
            
            if self._dataType == 'urlencoded' or self._dataType == 'json':
                
                for i in range (0, self._dataLen):

                    title = self._dataTable.getValueAt(i, 0)
                    baseValue = self._dataDict[title]

                    if 'submit' in title.lower() or 'submit' in self._dataDict[title].lower() or 'search' in title.lower() or 'search' in self._dataDict[title].lower():
                        continue

                    for value in self._simpleList:

                            self._dataTable.setValueAt(value, i, 1)

                            self.updateRequestViewer()
                            self.receiveResponse()

                    # Reset the table
                    self._dataTable.setValueAt(baseValue, i, 1)

            elif self._dataType == 'xml':

                for i in range (0, self._dataLen):

                    title = self._dataTable.getValueAt(i, 0)
                    baseValue = self._dataDict[title]

                    for value in self._xmlList:

                        # Update the table in case the loop interrupt in the middle
                        self._dataTable.setValueAt(value, i, 1)

                        # Send & request the HTTP request/response
                        self.updateRequestViewer()
                        self.receiveResponse()

                    # Reset the table
                    self._dataTable.setValueAt(baseValue, i, 1)

    '''
    Level 2 auto: loop through the data as well as the user agent (if exist)
    '''
    def autoScan2(self):
        
        # If the User-Agent does not exist, only performs level 1 auto 
        if self._userAgent != '':

            baseUserAgent = self._userAgent
            baseExpression = 'User-Agent: ' + baseUserAgent

            for value in self._simpleList:
                oldExpression = 'User-Agent: ' + self._userAgent
                newExpression = 'User-Agent: ' + value

                # Update the values accordingly
                requestBodyString = self._helpers.bytesToString(self._requestBody)
                self._requestBody = requestBodyString.replace(oldExpression, newExpression)
                self._userAgent = value

                self.updateRequestViewer()
                self.receiveResponse()
            
            # Reset the value back to original after each loop
            requestBodyString = self._helpers.bytesToString(self._requestBody)
            self._requestBody = requestBodyString.replace(newExpression, baseExpression)
            self._savedUserAgent = baseUserAgent
            self.updateRequestViewer()

        # Perform level 1 scan also
        self.autoScan1()

    '''
    Level 3 auto: Alpha: use the timer to perform blind insertion
    '''
    # TODO: 目前只支持GET/urlencoded，后续添加更多支持
    def autoScan3(self):

        self._timeReach = False
        timer = Timer(5, self.timeReach)

        # Modify the first element to perform blind injection
        title = self._dataTable.getValueAt(i, 0) 
        oldExpression = title + '=' + self._dataDict[title]
        newExpression = title + '=' + '1\' and if(1=0,1, sleep(10)) --+'


        if self._postGet == 'GET':

            # Update the values accordingly
            requestBodyString = self._helpers.bytesToString(self._requestBody)
            self._requestBody = requestBodyString.replace(oldExpression, newExpression)
            self._requestDataGet = self._requestDataGet.replace(oldExpression, newExpression)
            self._requestUrl = self._requestUrl.replace(oldExpression, newExpression)
            self._dataDict[title] = '1\' and if(1=0,1, sleep(10)) --+'
            self._requestModel.setValueAt('1\' and if(1=0,1, sleep(10)) --+', 0, 1)

        elif self._postGet == 'POST':

            if self._dataType == 'urlencoded':
                
                # Update the values accordingly
                requestBodyString = self._helpers.bytesToString(self._requestBody)
                self._requestBody = requestBodyString.replace(oldExpression, newExpression)
                self._requestData = self._requestData.replace(oldExpression, newExpression)
                self._dataDict[title] = '1\' and if(1=0,1, sleep(10)) --+'
                self._requestModel.setValueAt('1\' and if(1=0,1, sleep(10)) --+', 0, 1)

            else:
                print('autoScan3: _dataType not supported')

        else:
            print('autoScan3: _postGet not defined')

        timer.start()

        self.updateRequestViewer()
        self.receiveResponse()

        # Print the result
        if self._timeReach:
            print('Delay scan succeed')
        else:
            print('Delay scan failed')

        # Cancel the timer
        timer.cancel()


    def timeReach(self):
        self._timeReach = True

    '''
    Fetch the 'abnormal' payloads that shows very different response length from the normal ones
    '''
    def getAbnormal(self, basis, coefficient):
        
        # If the basis is not set, do nothing
        abnormList = ArrayList()
        if basis == 0:
            return None

        # Fetch the abnormals from the log list
        for log in self._log:
            if float(log._responseLen) / float(basis) < coefficient or float(basis) / float(log._responseLen) < coefficient:
                abnormList.append(log._payload)

        return abnormList

    '''
    Turn a simple dict of key/value pairs into XML
    '''
    def dictToXml(self, tag, d):
        
        elem = Element(tag)

        for key, val in d.items():
            child = Element(key)
            child.text = str(val)
            # Add element in reverse order so that the result is correct
            elem.insert(0, child)

        return elem

    '''
    initRequestInfo
    '''
    def initRequestInfo(self):
        self._postGet = ''
        self._userAgent = ''
        self._requestUrl = ''
        self._requestBody = ''
        self._requestData = ''
        self._requestDataGet = ''
        self._httpService = None
        self._dataDict = {}
        self._dataType = ''
        self._dataLen = 0
        self._attr = ''
        self._contentLength = 0
        self._currentlyDisplayedItem = None

    '''
    initResponseInfo
    '''
    def initResponseInfo(self):
        self._responseBody = None
        self._responseMessage = None
        self._responseLength = ''

    '''
    printRequest
    '''
    def printRequest(self):
        print('----------------')
        print(self._postGet)
        print('----------------')
        print(self._userAgent)
        print('----------------')
        print(self._requestUrl)
        print('----------------')
        print(self._requestBody)
        print('----------------')
        print(self._requestData)
        print('----------------')
        print(self._requestDataGet)
        print('----------------')
        print(self._httpService)
        print('----------------')
        print(self._dataDict)
        print('----------------')
        print(self._dataLen)
        print('----------------')
        print(self._attr)
        print('----------------')

    '''
    printResponse
    '''
    def printResponse(self):
        print('----------------')
        print(self._responseBody)
        print('----------------')
        print(self._responseMessage)
        print('----------------')
        print(self._responseLength)
        print('----------------')

'''
Listeners: TableModelListener for DefaultTableModel, and ActionListener for JButtons
'''
class Guis_Listeners(TableModelListener, ActionListener):

    def __init__(self, extender, absTable):
        self._extender = extender
        self._absTable = absTable

    '''
    Implement JTable, if the table is changed also change the value to be sent in the request body
    '''
    def tableChanged(self, e):
        row = e.getFirstRow()
        col = e.getColumn()

        # Skip this function when the table is changed by the program itself instead of user
        if col == -1:
            return

        # If the modified element is user agent, update the header directly
        if self._extender._dataTable.getValueAt(row, 0) == 'User-Agent':

            oldExpression = 'User-Agent: ' + self._extender._userAgent
            newExpression = 'User-Agent: ' + self._extender._dataTable.getValueAt(row, 1)

            requestBodyString = self._extender._helpers.bytesToString(self._extender._requestBody)
            self._extender._requestBody = requestBodyString.replace(oldExpression, newExpression)

            self._extender._userAgent = self._extender._dataTable.getValueAt(row, 1)

        # If the modified element is URL, update the table according to the modification
        elif self._extender._dataTable.getValueAt(row, 0) == 'URL':

            oldExpression = self._extender._requestUrl
            newExpression = self._extender._dataTable.getValueAt(row, 1)

            requestBodyString = self._extender._helpers.bytesToString(self._extender._requestBody)
            self._extender._requestBody = requestBodyString.replace(oldExpression, newExpression)

            self._extender._requestUrl = self._extender._dataTable.getValueAt(row, 1)
            if '?' in self._extender._requestUrl:
                self._extender._requestDataGet = re.sub('\S*\?', '', self._extender._requestUrl, re.IGNORECASE)
           
            else:
                print('tableChanged: no parameter in GET url')

            # Since user is able to modify the data arbitrarily by URL, clear the table and refill it
            self._extender._dataLen = 0
            self._extender._dataDict.clear()
            self._extender._dataTable.setRowCount(0)

            # Refill the table and dict
            dataList = self._extender._requestDataGet.split('&')
            for data in dataList:

                if '=' in data:

                    x = data.split('=', 1)
                    self._extender._dataDict[str(x[0])] = str(x[1])
                    self._extender._dataTable.addRow([str(x[0]), str(x[1])])
                    self._extender._dataLen += 1

            self._extender._dataTable.addRow(['URL', self._extender._requestUrl])
            self._extender._UrlRow = self._extender._dataLen

            if self._extender._userAgent != '':
                self._extender._dataTable.addRow(['User-Agent', self._extender._userAgent])

        # The data section is modified
        else:
            # If modified GET data, update URL accordingly
            if self._extender._postGet == 'GET':

                title = self._extender._dataTable.getValueAt(row, 0)
                value = self._extender._dataTable.getValueAt(row, 1)
                oldExpression = title + '=' + self._extender._dataDict[title]
                newExpression = title + '=' + value

                requestBodyString = self._extender._helpers.bytesToString(self._extender._requestBody)
                self._extender._requestBody = requestBodyString.replace(oldExpression, newExpression)
                self._extender._requestUrl = self._extender._requestUrl.replace(oldExpression, newExpression)
                self._extender._requestDataGet = self._extender._requestData.replace(oldExpression, newExpression)

                self._extender._dataDict[title] = value

                self._extender._dataTable.setValueAt(self._extender._requestUrl, self._extender._UrlRow, 1)
            
            elif self._extender._postGet == 'POST':

                if self._extender._dataType == 'urlencoded':

                    title = self._extender._dataTable.getValueAt(row, 0)
                    value = self._extender._dataTable.getValueAt(row, 1)
                    oldExpression = title + '=' + self._extender._dataDict[title]
                    newExpression = title + '=' + value

                    requestBodyString = self._extender._helpers.bytesToString(self._extender._requestBody)
                    self._extender._requestBody = requestBodyString.replace(oldExpression, newExpression)
                    self._extender._requestData = self._extender._requestData.replace(oldExpression, newExpression)

                    self._extender._dataDict[title] = value

                elif self._extender._dataType == 'json':

                    title = self._extender._dataTable.getValueAt(row, 0)
                    value = self._extender._dataTable.getValueAt(row, 1)

                    oldExpression = '\"' + title + '\":\"' + str(self._extender._dataDict[title]) + '\"'
                    newExpression = '\"' + title + '\":\"' + value + '\"'

                    requestBodyString = self._extender._helpers.bytesToString(self._extender._requestBody)
                    self._extender._requestBody = requestBodyString.replace(oldExpression, newExpression)
                    self._extender._requestData = self._extender._requestData.replace(oldExpression, newExpression)

                    self._extender._dataDict[title] = value

                elif self._extender._dataType == 'xml':

                    title = self._extender._dataTable.getValueAt(row, 0)
                    value = self._extender._dataTable.getValueAt(row, 1)

                    oldExpression = str(tostring(self._extender.dictToXml(self._extender._attr, self._extender._dataDict)))
                    self._extender._dataDict[title] = value
                    newExpression = str(tostring(self._extender.dictToXml(self._extender._attr, self._extender._dataDict)))

                    requestBodyString = self._extender._helpers.bytesToString(self._extender._requestBody)
                    self._extender._requestBody = requestBodyString.replace(oldExpression, newExpression)
                    self._extender._requestData = self._extender._requestData.replace(oldExpression, newExpression)

                    self._extender._dataDict[title] = value

            else:
                print('tableChanged: _postGet not Initialzed')

    '''
    Action listener for buttons
    '''
    def actionPerformed(self, e):
        # Hit Once
        if e.getSource() == self._extender._hitOnceButton:
            self._extender.receiveResponse()

        # Auto Scan
        if e.getSource() == self._extender._autoScanButton:

            if int(self._extender._levelSelection.getSelectedItem()) == 1:
                self._extender.autoScan1()
            elif int(self._extender._levelSelection.getSelectedItem()) == 2:
                self._extender.autoScan2()
            elif int(self._extender._levelSelection.getSelectedItem()) == 3:
                self._extender.autoScan3()

            # Currently, the getAbnormal function is called when the Auto Scan button is clicked
            # TODO: Do a separate button for this feature
            abnormList = self._extender.getAbnormal(self._extender._basisLen, 0.8)
            if abnormList is not None:
                for i in range(0, abnormList.size()):
                    print(abnormList.get(i))

        # Cancel
        if e.getSource() == self._extender._cancelButton:
            # Enable the hit buttons
            self._extender._hitOnceButton.setEnabled(True)
            self._extender._autoScanButton.setEnabled(True)

            # Unblock the mutex
            self._extender._httpLock.release()

        # Clear Log
        if e.getSource() == self._extender._clearLogButton:
            self._extender._log.clear()
            self._absTable.fireTableStructureChanged()

        # Set Basis
        if e.getSource() == self._extender._setBasisButton:

            responseBody = self._extender._currentlyDisplayedItem.getResponse()
            responseInfo = self._extender._helpers.analyzeResponse(responseBody)
            responseHeaders = responseInfo.getHeaders()

            # Fetch the content length
            self._extender._basisLen = self._extender.fetchContentLength(responseHeaders)

            self._extender._basisLabel.setText('Basis: ' + self._extender._basisLen)

'''
Table Model for request data table, request table in the main class
'''
class Guis_DefaultTM(DefaultTableModel):

    def __init__(self):
        self.addColumn('Name')
        self.addColumn('Value')

    def isCellEditable(self, row, column):
        if column is not 1:
            return False
        else:
            return True

'''
Table Model for log table
'''
class Guis_AbstractTM(AbstractTableModel):

    def __init__(self, extender):
        self._extender = extender

    def getRowCount(self):
        try:
            return self._extender._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Type"
        if columnIndex == 1:
            return "Content Length"
        if columnIndex == 2:
            return "Payload"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._extender._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._type
        if columnIndex == 1:
            return logEntry._responseLen
        if columnIndex == 2:
            return logEntry._payload
        return ""

'''
Table that hold the log entries, use AbstractTableModel
'''
class Guis_LogTable(JTable, ActionListener):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(self._extender)
        rowSorter = TableRowSorter(self._extender)
        self.setRowSorter(rowSorter)
    
    def changeSelection(self, row, col, toggle, extend):
        self._extender._extender._newRow = self.convertRowIndexToModel(row)

        logEntry = self._extender._extender._log.get(self._extender._extender._newRow)
        self._extender._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._extender._currentlyDisplayedItem = logEntry._requestResponse

        JTable.changeSelection(self, row, col, toggle, extend)
        
'''
Hold details of each log entry
'''
class LogEntry:

    def __init__(self, httpType, payload, requestResponse, responseLen):
        self._type = httpType
        self._payload = payload
        self._requestResponse = requestResponse
        self._responseLen = responseLen

'''
XML string parser (xml -> dict)
'''
class XMLHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
        self.buffer = ""                  
        self.mapping = {}                
 
    def startElement(self, name, attributes):
        self.buffer = ""                  
 
    def characters(self, data):
        self.buffer += data                    
 
    def endElement(self, name):
        self.mapping[name] = self.buffer         
 
    def getDict(self):
        return self.mapping
