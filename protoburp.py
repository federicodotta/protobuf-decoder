# -*- coding: utf-8 -*-
from collections import OrderedDict
import base64
import importlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
import StringIO
import re
import gzip
import array
import platform
from urllib import unquote, quote_plus

# Patch dir this file was loaded from into the path
# (Burp doesn't do it automatically)
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe()))), 'Lib'))

from burp import IBurpExtender, IMessageEditorTab, IMessageEditorTabFactory, ITab, \
        IExtensionStateListener

# Deprecated, replaced by an implementation based on message_factory
#from google.protobuf.reflection import ParseMessage as parse_message

from google.protobuf.text_format import Merge as merge_message
from google.protobuf import message_factory

from java.awt.event import ActionListener, MouseAdapter
from java.lang import Boolean, RuntimeException
from java.io import FileFilter, File
from javax.swing import JButton, JFileChooser, JMenu, JMenuItem, JOptionPane, JPanel, JPopupMenu
from javax.swing.filechooser import FileNameExtensionFilter
from java.lang import System

from ui import ParameterProcessingRulesTable
from ui import decode_url_and_base64, encode_base64_and_url

CONTENT_PROTOBUF = ['application/protobuf', 'application/x-protobuf', 'application/x-protobuffer', 'application/x-protobuffer; charset=utf-8', 'application/octet-stream', 'application/grpc-web+proto']

PROTO_FILENAME_EXTENSION_FILTER = FileNameExtensionFilter("*.proto, *.py",
                                                          ["proto", "py"])
CONTENT_GZIP = ('gzip')

PYTHON2_BINARY = 'python2'

def detectProtocBinaryLocation():
    system = System.getProperty('os.name')
    arch = platform.architecture()[0]

    if arch == "32bit":
        if system == "Linux":
            os.chmod("./protoc-linux-32", 0755)
            return os.path.join(os.getcwd(), "protoc-linux-32")
        elif system.startswith("Mac "):
            os.chmod("./protoc-mac-32", 0755)
            return os.path.join(os.getcwd(), "protoc-mac-32")
        elif system.startswith("Windows "):
            return os.path.join(os.getcwd(), "protoc-windows.exe")
        else:
            raise RuntimeError("Unrecognized operating system: " + system)
    elif arch == "64bit":
        if system == "Linux":
            os.chmod("./protoc-linux-64", 0755)
            return os.path.join(os.getcwd(), "protoc-linux-64")
        elif system.startswith("Mac "):
            os.chmod("./protoc-mac-64", 0755)
            return os.path.join(os.getcwd(), "protoc-mac-64")
        elif system.startswith("Windows "):
            return os.path.join(os.getcwd(), "protoc-windows.exe")
        else:
            raise RuntimeError("Unrecognized operating system: " + system)
    else:
        raise RuntimeError("Unrecognized operating system architecture: " + arch)


PROTOC_BINARY_LOCATION = detectProtocBinaryLocation()

def isGzip(content):
    isGzip = False
    headers = content.getHeaders()

    # first header is the request/response line
    for header in headers[1:]:
        name, _, value = header.partition(':')
        if name.lower() == 'content-encoding':
            value = value.lower().strip()
            if value in CONTENT_GZIP:
                isGzip = True
    return isGzip

def gUnzip(gzipcontent):
    buf = StringIO.StringIO(gzipcontent)
    f = gzip.GzipFile(fileobj=buf)
    body = f.read()
    f.close()
    return body


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, ITab, IExtensionStateListener):
    EXTENSION_NAME = "Protobuf Decoder"

    def __init__(self):
        self.descriptors = OrderedDict()

        self.chooser = JFileChooser()
        self.chooser.addChoosableFileFilter(PROTO_FILENAME_EXTENSION_FILTER)
        self.chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES)
        self.chooser.setMultiSelectionEnabled(True)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.enabled = False

        try:
            process = subprocess.Popen([PROTOC_BINARY_LOCATION, '--version'],
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            output, error = process.communicate()
            self.enabled = output.startswith('libprotoc')

            if error:
                raise RuntimeError(error)

        except (OSError, RuntimeError) as error:
            self.callbacks.getStderr().write(
                    "Error calling protoc: %s\n" % (error.message, ))

        if not self.enabled:
            return

        rules = []
        '''
        saved_rules = callbacks.loadExtensionSetting('rules')

        if saved_rules:
            rules = json.loads(base64.b64decode(saved_rules))

            # For checkboxes to be rendered in a table model, the
            # type has to be java.lang.Boolean, not a Python bool.

            for rule in rules:
                rule[-1] = Boolean(rule[-1])
        '''

        self.table = ParameterProcessingRulesTable(self, *rules)

        callbacks.setExtensionName(self.EXTENSION_NAME)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.addSuiteTab(self)
        return

    def createNewInstance(self, controller, editable):
        return ProtobufEditorTab(self, controller, editable)

    def getTabCaption(self):
        return self.EXTENSION_NAME

    def getUiComponent(self):
        return self.table

    def extensionUnloaded(self):
        if not self.table.rules:
            return

        rules = self.table.rules

        # The default JSONENcoder cannot dump a java.lang.Boolean type,
        # so convert it to a Python bool. (We'll have to change it back
        # when loading the rules again.

        for rule in rules:
            rule[-1] = bool(rule[-1])

        self.callbacks.saveExtensionSetting(
                'rules', base64.b64encode(json.dumps(rules)))
        return


class ProtobufEditorTab(IMessageEditorTab):
    TAB_CAPTION = "Protobuf Decoder"


    def __init__(self, extender, controller, editable):
        self.extender = extender
        self.callbacks = extender.callbacks
        self.helpers = extender.helpers
        self.controller = controller
        self.editable = editable

        self.descriptors = extender.descriptors
        self.chooser = extender.chooser

        self.listener = LoadProtoActionListener(self)

        self._current = (None, None, None, None)

        self.editor = extender.callbacks.createTextEditor()
        self.editor.setEditable(editable)

        self.filter_search = None

        mouseListener = LoadProtoMenuMouseListener(self)
        self.getUiComponent().addMouseListener(mouseListener)

        self.last_proto = None

    def getTabCaption(self):
        return self.TAB_CAPTION

    def getUiComponent(self):
        return self.editor.getComponent()

    def isEnabled(self, content, isRequest):
        if not self.extender.enabled:
            return False

        if isRequest:

            # Necessary sometimes when content-type is not set
            #return True 

            info = self.helpers.analyzeRequest(content)

            # check if request contains a specific parameter

            for parameter in info.getParameters():
                if parameter.getName() in self.extender.table.getParameterRules():
                    return True

            headers = info.getHeaders()
            
        else:

            # Necessary sometimes when content-type is not set
            #return True 

            headers = self.helpers.analyzeResponse(content).getHeaders()

        # first header is the request/response line

        for header in headers[1:]:
            name, _, value = header.partition(':')
            if name.lower() == 'content-type':
                value = value.lower().strip()
                if value in CONTENT_PROTOBUF:
                    return True
        return False

    #whenever string is loaded to grpc-web-proto editor tab
    def setMessage(self, content, isRequest):
        if content is None:
            self.editor.setText(None)
            self.editor.setEditable(False)
            return

        if isRequest:
            info = self.helpers.analyzeRequest(content)
        else:
            info = self.helpers.analyzeResponse(content)

        # by default, let's assume the entire body is a protobuf message

        # check if body is compressed (gzip)
        # gunzip the content first if required

        if isGzip(info):

            #if isRequest:
            #    print "Request body is using gzip: Uncompressing..."            
            #else:
            #    print "Response body is using gzip: Uncompressing..."            

            body = gUnzip(content[info.getBodyOffset():].tostring())
        else:
            body = content[info.getBodyOffset():].tostring()

        # process parameters via rules defined in Protobuf Decoder ui tab

        parameter = None

        for name, rules in self.extender.table.getParameterRules().iteritems():
            parameter = self.helpers.getRequestParameter(content, name)

            if parameter is not None:

                # no longer use the entire message body as the protobuf
                # message, just the value of the parameter according
                # to our ui defined rules

                body = parameter.getValue().encode('utf-8')

                for rule in rules.get('before', []):
                    body = rule(body)
                                        
                break

        if parameter is None:
            #set message
            rawBytes = (content[info.getBodyOffset():])
            global oldPadding
            global hasPadding 
            hasPadding = False

            oldPadding= rawBytes[0:4]
            if rawBytes[0] == 0 and rawBytes[1] == 0 and rawBytes[2] == 0 and rawBytes[3] == 0:
                rawBytes = rawBytes[5:rawBytes[4]+5]
                hasPadding = True
            body = rawBytes.tostring()


        # If we already selected a proto for this specific tab, continue to use that very proto

        if(self.last_proto is not None):

            factory = message_factory.MessageFactory()
            klass = factory.GetPrototype(self.descriptor)
            klass_instance = klass()
            klass_instance.ParseFromString(body)

            message = klass_instance

            self.tab.editor.setText(str(klass_instance))
            self.tab.editor.setEditable(True)
            self.tab._current = (content, message, info, parameter)
            return
        
        # 1 - Loop through all proto descriptors loaded and use the first that matches
        '''        
        for package, descriptors in self.descriptors.iteritems():
            for name, descriptor in descriptors.iteritems():
                try:
                    print "Parsing message with proto descriptor %s (auto)." % (name)
                    message = parse_message(descriptor, body)
                except Exception:
                    print "(exception parsing message... - continue)"
                    continue

                # Stop parsing on the first valid message we encounter
                # this may result in a false positive, so we should still
                # allow users to specify a proto manually (select from a
                # context menu).

                if message.IsInitialized():
                    # The message is initialized if all of its
                    # required fields are set.
                    #print "Message: [%s]" % (message)

                    if str(message) == "":
                        # parse_message() returned an empty message, but no
                        # error or exception: continue to the next proto descriptor
                        print "(message is empty, trying other proto descriptors...)"
                    else:
                        self.editor.setText(str(message))
                        self.editor.setEditable(True)
                        self._current = (content, message, info, parameter)
                        return
        '''

        # 2 - This implementation prints the results of all the protos that matches
        '''
        content_pane = ""
        
        # Loop through all proto descriptors loaded
        for package, descriptors in self.descriptors.iteritems():
            for name, descriptor in descriptors.iteritems():
                try:
                    print "Parsing message with proto descriptor %s (auto)." % (name)
                    message = parse_message(descriptor.Request, body)
                except Exception:
                    print "(exception parsing message... - continue)"
                    continue

                # Stop parsing on the first valid message we encounter
                # this may result in a false positive, so we should still
                # allow users to specify a proto manually (select from a
                # context menu).

                if message.IsInitialized():
                    # The message is initialized if all of its
                    # required fields are set.
                    #print "Message: [%s]" % (message)

                    if str(message) == "":
                        # parse_message() returned an empty message, but no
                        # error or exception: continue to the next proto descriptor
                        print "(message is empty, trying other proto descriptors...)"
                    else:

                        content_pane = content_pane + "***** " +  str(name) + " - " + str(package) + "\n"
                        content_pane = content_pane + str(message) + "\n"

        if(content_pane != ""):
            self.editor.setText(str(content_pane))
            self.editor.setEditable(False)
            self._current = (content, content_pane, info, parameter)
            return
        '''

        # 3 - This implementation (the one that I prefer) decodes without protos with protoc if no proto is selected
        process = subprocess.Popen([PROTOC_BINARY_LOCATION, '--decode_raw'],
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        output = error = None
        try:
            output, error = process.communicate(body)
        except OSError:
            pass
        finally:
            if process.poll() != 0:
                process.wait()

        if error:
            #print "protoc displaying message - error..."
            self.editor.setText(error)
        else:
            #print "protoc displaying message - output..."
            self.editor.setText(output)

        self.editor.setEditable(False)
        self._current = (content, None, info, parameter)
        return

    def getMessage(self):
        content, message, info, parameter = self._current

        if message is not None and self.isModified():

            # store original so we can revert if needed

            original = message.SerializeToString()
            message.Clear()

            try:
                merge_message(self.editor.getText().tostring(), message) 

                headers = info.getHeaders()
                serialized = message.SerializeToString()
               
                if parameter is None and hasPadding:
                    oldPadding.append(len(serialized))
                    serialized = oldPadding.tostring() + serialized
                
                if parameter is not None:
                    rules = self.extender.table.getParameterRules().get(parameter.getName(), {})

                    for rule in rules.get('after', []):
                        serialized = rule(serialized)                                                                

                    param = self.helpers.buildParameter(
                            parameter.getName(), serialized, parameter.getType())

                    return self.helpers.updateParameter(content, param)
                else:
                    return self.helpers.buildHttpMessage(headers, serialized)

            except Exception as error:
                JOptionPane.showMessageDialog(self.getUiComponent(),
                    error.message + str(traceback.format_exc()), 'Error parsing message!',
                    JOptionPane.ERROR_MESSAGE)

                # an error occurred while re-serializing the message,
                # revert back to the original

                message.Clear()
                message.MergeFromString(original)

        return content

    def isModified(self):
        return self.editor.isTextModified()

    def getSelectedData(self):
        return self.editor.getSelectedText()


class LoadProtoMenuMouseListener(MouseAdapter):
    def __init__(self, tab):
        self.tab = tab

    def mousePressed(self, event):
        return self.handleMouseEvent(event)

    def mouseReleased(self, event):
        return self.handleMouseEvent(event)

    # Recursive method necessary to add also subtimes (a message can have inside other message definitions...)
    def populate_menu_recursive(self, descriptors, fatherMenu, father_match):

        iter_found = False

        single_father_match = father_match
        total_father_match = father_match

        # if self.tab.filter_search is None:

        for name, descriptor in descriptors.iteritems():

            current_nested_dict = descriptor.nested_types_by_name

            if self.tab.filter_search is not None:
                single_father_match = father_match or re.search(self.tab.filter_search, name, re.IGNORECASE)
                total_father_match = total_father_match or re.search(self.tab.filter_search, name, re.IGNORECASE)

            if(len(current_nested_dict) > 0):

                protoMenu = JMenu(name)

                # The father is the messsage that encloses other messages
                enclosureOBject = JMenuItem("* Father")
                enclosureOBject.addActionListener(DeserializeProtoActionListener(self.tab, descriptor))
                protoMenu.add(enclosureOBject)
                
                if self.populate_menu_recursive(current_nested_dict, protoMenu, single_father_match) or self.tab.filter_search is None:
                    fatherMenu.add(protoMenu)
                    iter_found = True

            else:

                if self.tab.filter_search is None or re.search(self.tab.filter_search, name, re.IGNORECASE) or single_father_match:

                    protoMenu = JMenuItem(name)
                    protoMenu.addActionListener(DeserializeProtoActionListener(self.tab, descriptor))
                    fatherMenu.add(protoMenu)

                    iter_found = True

        return iter_found or total_father_match


    def handleMouseEvent(self, event):
        if event.isPopupTrigger():
            loadMenu = JMenuItem("Load .proto")
            loadMenu.addActionListener(self.tab.listener)

            popup = JPopupMenu()
            popup.add(loadMenu)

            filterMenu = JMenuItem("Filter .proto")
            filterMenu.addActionListener(SearchProtoActionListener(self.tab, event.getComponent()))
            popup.add(filterMenu)            

            if self.tab.descriptors:

                deserializeAsMenu = JMenu("Deserialize As...")

                popup.addSeparator()
                popup.add(deserializeAsMenu)

                # Raw deserialize using protoc without proto (it cannot be serialized if modified)
                rawMenu = JMenuItem("Raw")
                deserializeAsMenu.add(rawMenu)
                rawMenu.addActionListener(DeserializeProtoActionListener(self.tab, "raw"))
          
                for pb2, descriptors in self.tab.descriptors.iteritems(): 
                    
                    subMenu = JMenu(pb2)

                    if self.populate_menu_recursive(descriptors, subMenu, self.tab.filter_search is None):
                        deserializeAsMenu.add(subMenu)

            popup.show(event.getComponent(), event.getX(), event.getY())

        return


class ListProtoFileFilter(FileFilter):
    def accept(self, f):
        basename, ext = os.path.splitext(f.getName())
        if ext == '.proto' or (ext == '.py' and basename.endswith('_pb2')):
            return True
        else:
            return False


class LoadProtoActionListener(ActionListener):
    def __init__(self, tab):
        self.chooser = tab.chooser
        self.descriptors = tab.descriptors
        self.tab = tab

    def updateDescriptors(self, name, module):
        if module.DESCRIPTOR.message_types_by_name and name not in self.descriptors:
            descriptors = self.descriptors.setdefault(name, {})
            descriptors.update(module.DESCRIPTOR.message_types_by_name)

        for name, module_ in inspect.getmembers(module, lambda x: hasattr(x, 'descriptor_pb2')):
            self.updateDescriptors(name, module_)

        return

    # Method created to handle the situation in which a proto depends on another proto. In this situation the dependencies are imported recursively.
    def importProtoFileRecusive(self, proto):

        try:
            module = compile_and_import_proto(proto)
            if module:
                return module
            
        except (Exception, RuntimeException) as error:
            
            missing_module_regex = re.search('No module named (.*)_pb2', str(error))
            compilation_regex = re.search('.*Module or method too large in `(.*)`.*', str(error)) #
            
            if(missing_module_regex):                
                missing_module = missing_module_regex.group(1) + ".proto"                
                self.tab.callbacks.getStdout().write('*** %s depends on %s. Trying to import it...!\n' % (proto, missing_module, ))
                if self.importProtoFileRecusive(File(proto.getParent(),missing_module)):
                    return self.importProtoFileRecusive(proto)
                else:
                    self.tab.callbacks.getStderr().write('*** ERROR, infinite recursion with proto %s!\n' % (str(proto.getAbsolutePath()), ))
            
            # This compile with python pb2 too large
            elif(compilation_regex):
                subprocess.check_call([PYTHON2_BINARY, '-m', 'py_compile', compilation_regex.group(1)])
                return self.importProtoFileRecusive(proto)
            
            else:
                self.tab.callbacks.getStderr().write('*** ERROR in recursive import: %s!\n' % (str(error), ))
                tb = traceback.format_exc()
                self.tab.callbacks.getStderr().write('Traceback: %s!\n' % (str(tb), ))
                return None

    def importProtoFiles(self, selectedFiles):
        for selectedFile in selectedFiles:
            if selectedFile.isDirectory():
                self.chooser.setCurrentDirectory(selectedFile)
                self.importProtoFiles(selectedFile.listFiles(ListProtoFileFilter()))
            else:
                self.chooser.setCurrentDirectory(selectedFile.getParentFile())
                yield self.importProtoFileRecusive(selectedFile)


    def actionPerformed(self, event):
        if self.chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            for module in self.importProtoFiles(self.chooser.getSelectedFiles()):
                self.updateDescriptors(module.__name__, module)

        return


# The purpose is being able to search for protos, if we have tons of proto
class SearchProtoActionListener(ActionListener):
    def __init__(self, tab, component):
        self.tab = tab
        self.component = component

    def actionPerformed(self, event):    
        self.tab.filter_search = JOptionPane.showInputDialog(self.component, "Search: ", "Search", 1);


class DeserializeProtoActionListener(ActionListener):
    def __init__(self, tab, descriptor):
        self.tab = tab
        self.descriptor = descriptor

    def actionPerformed(self, event):
        content, message, info, parameter = self.tab._current

        try:

            # check if body is compressed (gzip)
            # gunzip the content first if required

            if isGzip(info):
                body = gUnzip(content[info.getBodyOffset():].tostring())
            else:
                body = content[info.getBodyOffset():].tostring()
                #body = content[info.getBodyOffset():]

            if parameter is not None:
                param = self.tab.helpers.getRequestParameter(
                        content, parameter.getName())

                if param is not None:
                    rules = self.tab.extender.table.getParameterRules().get(parameter.getName(), {})
                    body = param.getValue().encode('utf-8')

                    for rule in rules.get('before', []):
                        body = rule(body)

            if parameter is None:

                # cut 5 bytes for grpc web
                rawBytes = (content[info.getBodyOffset():])
                global oldPadding
                global hasPadding 
                hasPadding = False

                oldPadding= rawBytes[0:4]
                if rawBytes[0] == 0 and rawBytes[1] == 0 and rawBytes[2] == 0 and rawBytes[3] == 0:
                    rawBytes = rawBytes[5:]
                    hasPadding = True

                body = rawBytes.tostring()               
                #body = rawBytes

            if self.descriptor != "raw":

                print "Parsing message with proto descriptor %s (by user)." % (self.descriptor.name)

                # Deprecated method
                #message = parse_message(self.descriptor, body)
                
                factory = message_factory.MessageFactory()
                klass = factory.GetPrototype(self.descriptor)
                klass_instance = klass()
                klass_instance.ParseFromString(body)

                message = klass_instance

                self.tab.editor.setText(str(klass_instance))
                self.tab.editor.setEditable(True)
                self.tab._current = (content, message, info, parameter)
                self.tab.last_proto = self.descriptor

            else:

                print "Parsing message without any proto"

                process = subprocess.Popen([PROTOC_BINARY_LOCATION, '--decode_raw'],
                                           stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)


                output = error = None
                try:
                    output, error = process.communicate(body)
                except OSError:
                    pass
                finally:
                    if process.poll() != 0:
                        process.wait()

                if error:
                    #print "protoc displaying message - error..."
                    self.tab.editor.setText(error)                    
                else:
                    #print "protoc displaying message - output..."
                    self.tab.editor.setText(output)                    

                self.tab.editor.setEditable(False)
                self.tab._current = (content, None, info, parameter)

        except Exception as error:

            if self.descriptor != "raw":
                title = "Error parsing message as %s!" % (self.descriptor.name, )
            else:
                title = "Error parsing message as without any proto"
            JOptionPane.showMessageDialog(self.tab.getUiComponent(),
                error.message + str(traceback.format_exc()), title, JOptionPane.ERROR_MESSAGE)

            #print(str(error))
            #print(str(error.message))
            #print(str(traceback.format_exc()))

        return


def compile_and_import_proto(proto):
    curdir = os.path.abspath(os.curdir)
    tempdir = tempfile.mkdtemp()

    print(str(tempdir))

    is_proto = os.path.splitext(proto.getName())[-1] == '.proto'

    if is_proto:
        try:
            os.chdir(os.path.abspath(proto.getParent()))
            subprocess.check_call([PROTOC_BINARY_LOCATION, '--python_out',
                                  tempdir, proto.getName()])
            module = proto.getName().replace('.proto', '_pb2')

        except subprocess.CalledProcessError as e:
            print("*** ERROR COMPILING")
            print(e)
            shutil.rmtree(tempdir)
            return None

        finally:
            os.chdir(curdir)

    else:
        module = proto.getName().replace('.py', '')

    try:
        if is_proto:
            os.chdir(tempdir)
        else:
            os.chdir(proto.getParent())

        sys.path.append(os.path.abspath(os.curdir))

        # Added compilation in order to avoid error with big proto files
        subprocess.check_call([PYTHON2_BINARY, '-m', 'py_compile', str(module) + ".py"])

        return importlib.import_module(module)

    except subprocess.CalledProcessError as e:
    #except Exception as e:
        print("*** ERROR COMPILING")
        print(e)
        print(str(traceback.format_exc()))

    finally:
        sys.path.pop()
        os.chdir(curdir)
        shutil.rmtree(tempdir)

