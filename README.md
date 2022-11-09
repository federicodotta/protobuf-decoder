burp-protobuf-decoder
=====================

A simple Google Protobuf Decoder for Burp

My fork (federicodotta)
-------------

This is a fork of the Burp Suite version of burp-protobuf-decoder with many improvements and a lot of bug fixes:

- Recursive import have been added to the plugin: now if a proto depends on another one, the plugin look in the same folder to find for it. This process is recursive (all the messages showed in the previous screenshot have been recursively loaded as dependencies of a single proto file)
- The plugin now handles nested messages (messages that contain other messages) in a recursive manner and it is possible to choose any proto of the tree for deserialization. 
- A filter has been handled to search for a specific proto file, necessary because we had a lot of messages types and their number made them very difficult to find in the context menu
- A lot of bug fixes in the code actually present in the Portswigger BAppStore
- Protobuf library updated to one of the last versions compatible with Python2
- Protobuf library has been fixed in a couple of points because it uses a bytearray Python structure not fully compatible with Jython (small patch but quite difficult to debug)
- The extension used a deprecated way in the deserialization routines that has been replaced by a non-deprecated one
- The plugin handles big proto files by compiling .py files in .pyc. In this way it is not necessary to manually split large python files
- The plugin saves last proto used in a specific tab to speed up working with the Repeater
- Proto data in HTTP parameters fixed
- Base64 encode + URL (and viceversa) added to the supported encodings (the plugin supported only Base64 URL-safe but it is not the same and does not work in all the situations)
- GZIP decompression fixed and GZIP compression added (the current one handled only GZIP decompression and not compression for the edited content)

By default, if no message is selected, my fork gives the "raw" representation (deserialization using protoc binary without supplying any proto file) because this way I don't miss any data due to the deserialization using a wrong proto message. Two alternative implementations are included in the code (commented). The first one is the original one that tries to decode with every loaded messages, stopping on the first that does not throw an error. The second one, useful to quickly identify the right proto message to use, tries to decode the data with all the loaded proto messages without stopping on the first that matches and prints the results in the plugin standard output.

Requirements:

- To properly work it is necessary to manually set Python2 path in the "protoburp.py" file, in variable PYTHON2_BINARY at line 50. Python2 binary is used to compile big python proto files and overcome the python size limitations

More information on our company blog: https://security.humanativaspa.it/burp-suite-and-protobuf/

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


Old README (can be inaccurate)
=====================

Prerequisites
-------------

1. Burp Professional 
2. [Jython 2.7+](http://www.jython.org/downloads.html)


Install
-------

In Burp Store, install the Protobuf Decoder extension.


Frequently Asked Questions
--------------------------

- Why can't I edit a decoded proto message?

	> Serializing a message requires a proto file descriptor (\*.proto file).
	> Without this proto, we don't know how fields should be serialized.

- What if I have a proto file descriptor?

	> Load it from a Protobuf tab by right-clicking. Messages will be
	> automatically decoded from then on. If you wish to manually
	> deserialize a message as different type, this option is available to you 
	> via a right-click context menu once a proto is loaded.

	> By loading a .proto, you can edit and tamper protobuf messages.
	> The extension will automatically serialize messages back before
	> they're sent along.

- Can I deserialize protobufs passed as URL or form parameters?

    > Yes, you can. In the 'Protobuf Decoder' tab, add a parameter to
    > the table. You can specify additional pre and post processing
    > rules, to handle base64 encoding or zlib compression. Don't forget
    > to check the enabled box for each rule once you're done.

    > Note, the editor tab window may not immediately pick up the changes.
    > You can work around this issue by cycling through requests (anything
    > that'd trigger the editor tab to reload itself)

- What if I need to use another version of protobuf or need windows 64bit protoc?

    > Find the version that you want to use from https://github.com/protocolbuffers/protobuf/tags
    > 1. Download the right protoc file according to your OS and overwrite the binary included in this repo
    > 2. Download protobuf-python-3.x.x.zip, unzip it and move the google folder under protobuf-python-3.x.x/python to Lib/google.

Gotchas
-------

- Since Java doesn't support methods larger than 64k, big proto definitions need
  to be spit in multiple files. Otherwise, you get the error "Method code too
  large"

- proto2 files should always declare syntax = “proto2” in the header instead of
  leaving it implicit, otherwise it won't work since the default is proto v3
  
  

Protoc Versions
-------
https://github.com/protocolbuffers/protobuf/releases/tag/v3.2.0

Win 32 : v3.2.0 <br>
Mac 32 : v3.2.0 <br>
Mac 64 : v3.2.0 <br>
Linux 32 : v3.2.0 <br>
Linux 64 : v3.2.0 <br>

