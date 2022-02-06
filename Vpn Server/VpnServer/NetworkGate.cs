using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PcapDotNet.Core;
using PcapDotNet.Base;
using System.Threading;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Transport;
using SharpPcap;
using System.Collections;
using System.Windows;

namespace VpnServer
{
    public class NetworkGate
    {//Class that ressponsible for the local network, the monitoring, the packet send and receive
        private PacketDevice device;
        private ICaptureDevice sharpDevice;
        private PacketCommunicator communicator;
        private Hashtable networkComputersTable;
        private AidFunctions af;
        private string devIp;
        private string devMac;

        public NetworkGate(LivePacketDevice device, ICaptureDevice sharpDevice)
        {//Constructor - take the device, starting the communicator, device mac and ip
            this.device = device;
            this.sharpDevice = sharpDevice;
            communicator = device.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);
            networkComputersTable = new Hashtable();
            af = new AidFunctions();
            devIp = device.Addresses[1].Address.ToString().Split(' ')[1];//Local network device Ip
            devMac = af.AddDots(sharpDevice.MacAddress.ToString());//Local network device Mac
        }

        public void MonitorNetwork()
        {//Initialize Network Monitoring - starting the arp broadcast send and recive 
            Console.WriteLine("Monitoring The Local Network...");
            Thread receiver = new Thread(ReceiveArpResponses);
            receiver.Start();//Arp Responses Receiver Thread
            Thread sender = new Thread(SendArpBroadcast);
            sender.Start();//Arp Broadcast Sender Thread
            Thread.Sleep(3000);
            Console.WriteLine(networkComputersTable.Count + " Devices Detected");
            Console.WriteLine();
        }

        private void SendArpBroadcast()
        {//Creating Arp Broadcast packet and sending it to the local computers
            Thread.Sleep(300);
            EthernetLayer ethernetLayer = new EthernetLayer()
            {//Ethernet layer of the arp packet
                Source = new MacAddress(devMac),
                Destination = new MacAddress("FF:FF:FF:FF:FF:FF"),//Broadcast mac destination
                EtherType = EthernetType.None
            };

            string[] devipArr = devIp.Split('.');
            byte[] byteIp = Array.ConvertAll(devipArr, byte.Parse);//Server local Device Ip
            byte[] byteTargetIp = new byte[byteIp.Length];
            Array.Copy(byteIp, byteTargetIp, byteIp.Length - 1);//bytrTargetIp = Subnet Ip
            string[] devMacArr = devMac.Split(':');//Server local Device Mac
            byte[] byteMac = af.StringToByteArray(String.Join("", devMacArr));

            ArpLayer arpLayer = new ArpLayer()
            {//Arp layer of the arp packet
                Operation = ArpOperation.Request,
                ProtocolType = EthernetType.IpV4,
                SenderProtocolAddress = byteIp.AsReadOnly(),
                SenderHardwareAddress = byteMac.AsReadOnly(),//Ethernet source = local device mac
                TargetHardwareAddress = new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }.AsReadOnly()
                //Arp mac destination(packet asks for) = Broadcast mac 255:255:255:255
            };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, arpLayer);//Build the packet
            for (int i = 0; i < 256; i++)
            {//Send the packet to all the computers in the subnet except the server
                if (i != byteIp[byteIp.Length - 1])
                {
                    byteTargetIp[byteTargetIp.Length - 1] = (byte)i;
                    arpLayer.TargetProtocolAddress = byteTargetIp.AsReadOnly();//Arp ip destination
                    Packet packet = builder.Build(DateTime.Now);//Build the packet
                    communicator.SendPacket(packet);//Send the packet to the computer
                }
            }

        }

        private void ReceiveArpResponses()
        {
            PacketSniffer ps = new PacketSniffer(device, "arp-reply");
            for (; ; )
            {/*Loop that waits for arp responses from the local network
              openning every packet reading it and add the computer 
              information to the local network computers table*/
                Packet packet = ps.CapturePacket();
                if (packet.Ethernet.EtherType == EthernetType.Arp)
                {
                    if (packet.Ethernet.Arp.Operation == ArpOperation.Reply)
                    {
                        ArpDatagram arpD = packet.Ethernet.Arp;
                        if (!networkComputersTable.ContainsKey(arpD.SenderProtocolIpV4Address.ToString())
                            && !arpD.SenderProtocolIpV4Address.ToString().Equals(devIp))
                        {//Checking if the computer is not in the list and the packet is not from the server 
                            string destmac = BitConverter.ToString(arpD.SenderHardwareAddress.ToArray());
                            string[] d = destmac.Split('-');
                            destmac = string.Join(":", d);
                            networkComputersTable.Add(arpD.SenderProtocolIpV4Address.ToString(), destmac);
                            //Inserting the ip and mac address of the computer to the network computers table
                        }
                    }
                }
            }
        }

        public void TransferPacket(Packet packet, string direction)
        {
            Packet newPacket = null;
            IpV4Layer ipV4 = (IpV4Layer)packet.Ethernet.IpV4.ExtractLayer();
            EthernetLayer ethernet = (EthernetLayer)packet.Ethernet.ExtractLayer();

            if ((direction == "lan" && networkComputersTable.ContainsKey(ipV4.Destination.ToString())) ||
                (direction == "network" && MainWindow.vpnTunnels.ContainsKey(ipV4.Destination.ToString())))
            {/*Checking if the packet direction is the lan and the destination is one of the network
                computers or the direction is the network and the destination is one of the clients*/
                string destination = "";
                if (direction == "lan")
                {/*if the direction is lan - change the ethernet source of the packet from the client mac
                    to the ethernet source mac of the server and the ethernet destination of the packet 
                    to the local network computer*/
                    ethernet.Source = new MacAddress(devMac);
                    destination = networkComputersTable[ipV4.Destination.ToString()].ToString();
                }
                else
                {/*if the direction is network - change the ethernet destination 
                    to the ethernet source of client*/
                    destination = MainWindow.vpnTunnels[ipV4.Destination.ToString()].ClientMac;
                }
                ethernet.Destination = new MacAddress(destination);
                PacketBuilder pb;
                switch (ipV4.Protocol)
                {
                    case IpV4Protocol.InternetControlMessageProtocol://ICMP Packet
                        Console.WriteLine("Icmp Packet");
                        //Extract packet icmp and icmp payload layers
                        IcmpLayer icmp = (IcmpLayer)packet.Ethernet.IpV4.Icmp.ExtractLayer();
                        PayloadLayer icmpPayload = (PayloadLayer)packet.Ethernet.IpV4.Icmp.Payload.ExtractLayer();
                        pb = new PacketBuilder(ethernet, ipV4, icmp, icmpPayload);
                        newPacket = pb.Build(DateTime.Now);//Build the packet
                        Console.WriteLine("newPacket Source: " + newPacket.Ethernet.IpV4.Source);
                        if (direction == "lan")
                        {//If direction is lan - send the packet to the local network to the destination computer
                            Application.Current.Dispatcher.Invoke(new Action(() => { MainWindow.globalPacketLst.Items.Add("Icmp Request: " + ipV4.Destination.ToString() + "(" + packet.Ethernet.Destination.ToString() /* Client's Gateway's Mac*/  + ")<==" + ipV4.Source.ToString() + "(" + packet.Ethernet.Source.ToString() + ")"); }));
                            communicator.SendPacket(newPacket);
                            Application.Current.Dispatcher.Invoke(new Action(() => { MainWindow.localPacketLst.Items.Add("Icmp Request: " + newPacket.Ethernet.IpV4.Destination.ToString() + "(" + newPacket.Ethernet.Destination.ToString() + ")<==" + newPacket.Ethernet.IpV4.Source.ToString() + "(" + newPacket.Ethernet.Source.ToString() + ")"); }));
                        }
                        else
                        {//If direction is network - send the packet to the network to the destination client
                            Application.Current.Dispatcher.Invoke(new Action(() => { MainWindow.localPacketLst.Items.Add("Icmp Response: " + packet.Ethernet.IpV4.Source.ToString() + "(" + packet.Ethernet.Source.ToString() + ")==>" + packet.Ethernet.IpV4.Destination.ToString() + "(" + packet.Ethernet.Destination.ToString() + ")"); }));
                            MainWindow.vpnTunnels[packet.Ethernet.IpV4.Destination.ToString()].SendData(newPacket.Buffer);
                            Application.Current.Dispatcher.Invoke(new Action(() => { MainWindow.globalPacketLst.Items.Add("Icmp Response: " + newPacket.Ethernet.IpV4.Source.ToString() + "(" + newPacket.Ethernet.Source.ToString() + ")==>" + newPacket.Ethernet.IpV4.Destination.ToString() + "(" + newPacket.Ethernet.Destination.ToString() + ")"); }));
                        }

                        Console.WriteLine("PacketSent");
                        break;

                    case IpV4Protocol.Tcp://TCP Packet
                        Console.WriteLine("Tcp Packet");
                        //Extract packet tcp and tcp payload layers
                        TcpLayer tcp = (TcpLayer)packet.Ethernet.IpV4.Tcp.ExtractLayer();
                        PayloadLayer tcpPayload = (PayloadLayer)packet.Ethernet.IpV4.Tcp.Payload.ExtractLayer();
                        pb = new PacketBuilder(ethernet, ipV4, tcp, tcpPayload);
                        newPacket = pb.Build(DateTime.Now);//Build the packet
                        Console.WriteLine("newPacket Source: " + newPacket.Ethernet.IpV4.Source);
                        if (direction == "lan")
                        {//If direction is lan - send the packet to the local network to the destination computer
                            Application.Current.Dispatcher.Invoke(new Action(() => { MainWindow.globalPacketLst.Items.Add("Tcp Request: " + ipV4.Destination.ToString() + "(" + packet.Ethernet.Destination.ToString() /* Client's Gateway's Mac*/  + ")<==" + ipV4.Source.ToString() + "(" + packet.Ethernet.Source.ToString() + ")"); }));
                            communicator.SendPacket(newPacket);
                            Application.Current.Dispatcher.Invoke(new Action(() => { MainWindow.localPacketLst.Items.Add("Tcp Request: " + newPacket.Ethernet.IpV4.Destination.ToString() + "(" + newPacket.Ethernet.Destination.ToString() + ")<==" + newPacket.Ethernet.IpV4.Source.ToString() + "(" + newPacket.Ethernet.Source.ToString() + ")"); }));
                        }
                        else
                        {//If direction is network - send the packet to the network to the destination client
                            Application.Current.Dispatcher.Invoke(new Action(() => { MainWindow.localPacketLst.Items.Add("Tcp Response: " + packet.Ethernet.IpV4.Source.ToString() + "(" + packet.Ethernet.Source.ToString() + ")==>" + packet.Ethernet.IpV4.Destination.ToString() + "(" + packet.Ethernet.Destination.ToString() + ")"); }));
                            MainWindow.vpnTunnels[packet.Ethernet.IpV4.Destination.ToString()].SendData(newPacket.Buffer);
                            Application.Current.Dispatcher.Invoke(new Action(() => { MainWindow.globalPacketLst.Items.Add("Tcp Response: " + newPacket.Ethernet.IpV4.Source.ToString() + "(" + newPacket.Ethernet.Source.ToString() + ")==>" + newPacket.Ethernet.IpV4.Destination.ToString() + "(" + newPacket.Ethernet.Destination.ToString() + ")"); }));
                        }
                        Console.WriteLine("PacketSent");
                        break;
                }
            }
            else
                Console.WriteLine("Packet Destination Invalid" + ipV4.Destination.ToString());
        }

        public void ReceiveFromNetwork()
        {//Loop that listenning and sniffing packets from the local network and transfer them
            PacketSniffer ps = new PacketSniffer(device, "icmp or tcp or udp");
            for (; ; )
            {
                Packet packet = ps.CapturePacket();
                TransferPacket(packet,"network");
                Console.WriteLine("Reply Sent: " + packet.Ethernet.IpV4.Destination);
            }
        }

        public Hashtable NetworkComputersTable
        {
            get
            {
                return networkComputersTable;
            }
        }
    }
}
