# Deception-Solution

![project archiecture](https://github.com/Fatmamohamed486/Deception-Solution/assets/101456811/31c7d782-c19a-47f8-a666-fc2af34aa703)

This project aims to create a Network Deception Solution for providing real-time monitoring and alerting to enterprise network
the main idea is to alert when a malicious traffic reach the server, using traffic flow controller like fooldlight controller to redirect this malicious traffic to a honeypot
for furthure analysis.

we used KVM for creating Virtual machines using open vswitch to creat the virtual switch

sudo apt update
sudo apt upgrade
sudo apt install openvswitch-switch
sudo ovs-vswitchd

sudo ovs-vsctl add-br br0
#set the floodlight controller to the switch
sudo ovs-vsctl set-controller br0 tcp:192.168.100.40:6633                   
sudo ovs-vsctl set bridge br0 protocols=OpenFlow10

sudo ifconfig br0 up
sudo ip addr add 192.168.100.1/24 broadcast 192.168.100.255 dev br0

Then we add this switch to our machines using kvm xml for networks

<interface type='bridge'>
       <mac address='52:54:00:fb:00:02'/>
       <source bridge='br0'/>
       <virtualport type='openvswitch'/>
       <model type='virtio'/>
   </interface>

Note: change the mac address for each host

then for each virtual machine set the ip address and the gateway

Ifconfig enp6s0 192.168.100.10 netmask 255.255.255.0 broadcast 192.168.100.255
route add default gw 192.168.100.1

Note: change the interface based on the interface attached to each machine
check for it using *ifconfig*


