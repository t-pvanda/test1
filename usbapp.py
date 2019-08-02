import usb.core
import usb.util
import usb.backend.libusb1

# find our device
dev = usb.core.find()
print (usb.core.find())


dev = usb.core.find(find_all=True, bDeviceClass=True)

# was it found?
if dev is None:
    raise ValueError('Device not found')

# set the active configuration. With no arguments, the first
# configuration will be the active one
dev.set_configuration()

# get an endpoint instance
cfg = dev.get_active_configuration()
intf = cfg[(0,0)]

ep = usb.util.find_descriptor(
    intf,
    # match the first OUT endpoint
    custom_match = \
    lambda e: \
        usb.util.endpoint_direction(e.bEndpointAddress) == \
        usb.util.ENDPOINT_OUT)

assert ep is not None

# write the data
ep.write('test')

print("dur hello")
test_name = "DangName "
print("this is",test_name + "cool")
print ("numbers")
print(len(test_name))
print (4+5*3)
strIn = input ("yo dork, sup? ")
print ("doofus doin " +strIn)
