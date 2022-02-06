using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Threading;
using System.Threading.Tasks;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using SharpPcap;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Ethernet;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Collections;

namespace VpnServer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static NetworkGate networkGate;
        public static Dictionary<string, VpnTunnel> vpnTunnels;//Dictionary contians the vpnTunnels
        private static IList<LivePacketDevice> allDevices;//Network Devices
        public static ListBox serverComputersLst;
        public static ListBox clientsLst;
        public static ListBox localPacketLst;
        public static ListBox globalPacketLst;
        public static ListBox dBox;
        public static CheckBox icmpCheck;
        public static CheckBox tcpCheck;
        public static CheckBox udpCheck;
        public static string selectionText;

        public MainWindow()
        {//Initialize the server GUI and the network computers connection
            InitializeComponent();
            serverComputersLst = serverComputersListBox;
            clientsLst = clientsList;
            localPacketLst = localPacketListBox;
            globalPacketLst = globalPacketListBox;
            icmpCheck = policyIcmp;
            tcpCheck = policyTcp;
            udpCheck = policyUdp;
            selectionText = "no selection";
            Console.WriteLine(GetLocalIPAddress());
            InitNetworkGate();//Initialize the network gate
            foreach (DictionaryEntry entry in networkGate.NetworkComputersTable)
            {//Writing all the network computers on the list box
                Application.Current.Dispatcher.Invoke(new Action(() => {
                    MainWindow.serverComputersLst.Items.Add("Ip: " + 
                        entry.Key.ToString() + " Mac: " + entry.Value.ToString()); }));
            }
            Thread vpnServerThread = new Thread(InitializeServer);
            vpnServerThread.Start();//Starting the thread that initialize the server 
        }

        public static void InitializeServer()
        {//Initialize the server - Connection with clients, tunnels and recive threads
            vpnTunnels = new Dictionary<string, VpnTunnel>();//Creating vpnTunnels Dictionary
            int port = 4466;
            Console.WriteLine("Server Started");
            TcpListener tcpListener = new TcpListener(IPAddress.Any, port);
            tcpListener.Start();//Starting the tcp listener 
            for (; ; )
            {
                VpnTunnel t1 = new VpnTunnel("localhost", port, "1234");//Creating the vpnTunnel Object
                t1.ConnectToTunnel(tcpListener.AcceptTcpClient());/*Listenning on a port 
                        and waiting for connection from the clients and connect to client*/
                if (!vpnTunnels.ContainsKey(t1.ClientIp) && t1.IsAuthenticate(networkGate.NetworkComputersTable))
                { //Checking if authentication succeed - Add the vpnTunnel into the  dictionary and write information
                    vpnTunnels.Add(t1.ClientIp, t1); 
                    Application.Current.Dispatcher.Invoke(new Action(() => {
                        MainWindow.clientsLst.Items.Add("Ip: " + t1.ClientIp + "Mac: " + t1.ClientMac); }));
                    Thread Receiver = new Thread(() => ReceiveFromClient(t1));
                    Receiver.Start();//Starting the thread that receiving data from the client
                    Thread.Sleep(800);  
                }
                else
                {//Authentication faild - close connection
                    t1.CloseConnection();
                }
            }
        }

        public static void InitNetworkGate()
        {//The Function building the networkgate object by the network device
            allDevices = LivePacketDevice.AllLocalMachine;
            CaptureDeviceList devices = CaptureDeviceList.Instance;
            ICaptureDevice capDevice = null;
            string dName = allDevices[0].Name;
            dName = dName.Substring(dName.IndexOf('{') + 1, (dName.IndexOf('}') - dName.IndexOf('{') - 1));
            foreach (ICaptureDevice dev in devices)
            {//Open the sharpPcap devices equals to the Pcap device by the name
                dev.Open();
                string name = dev.Name;
                name = name.Substring(name.IndexOf('{') + 1, (name.IndexOf('}') - name.IndexOf('{') - 1));
                if (dName.Equals(name))
                {
                    capDevice = dev;
                }
            }
            networkGate = new NetworkGate(allDevices[0], capDevice);
            networkGate.MonitorNetwork();//Creating the networkGate Objecrt and starting the network monitor
            Thread networkReceiver = new Thread(networkGate.ReceiveFromNetwork);
            networkReceiver.Start();//Stariting the local network receiver thread
        }

        public static void ReceiveFromClient(VpnTunnel t1)
        {
            for (; ; )
            {/*Loop that listenning to the connection with the client, receiving the data
              building packet from the data and transfering it to the local netowrk*/
                try
                {
                    byte[] data = t1.ReceiveData();//Recive data from the client
                    Packet packet = new Packet(data, DateTime.Now, DataLinkKind.IpV4);
                    IpV4Datagram ipV4 = packet.Ethernet.IpV4;
                    if (ipV4 != null)
                    {//Chicking if packet received is valid
                        if (vpnTunnels.ContainsKey(ipV4.Source.ToString()))
                        {//Checking if the packet ip source is one of the clients
                            if (networkGate.NetworkComputersTable.ContainsKey(ipV4.Destination.ToString()))
                            {//Checking if the packet ip destination is one of the local network computers
                                if ((ipV4.Protocol == IpV4Protocol.InternetControlMessageProtocol && t1.TransferIcmp) ||
                                    (ipV4.Protocol == IpV4Protocol.Tcp && t1.TransferTcp))
                                {
                                    networkGate.TransferPacket(packet, "lan");//Transfer the packet into the nerwork
                                }
                            }
                        }
                    }

                }
                catch (Exception e)
                {//Lost connection with the client - close connection
                    Console.WriteLine("Error: " + e.Message);
                    vpnTunnels.Remove(t1.ClientIp);
                    Application.Current.Dispatcher.Invoke(new Action(() =>
                    {
                        MainWindow.clientsLst.Items.Remove(t1);
                    }));
                    t1.CloseConnection();
                    return;
                }

                Console.WriteLine();
                Console.WriteLine();
            }
        }

        public static string GetLocalIPAddress()
        {
            string strHostName = "";
            strHostName = System.Net.Dns.GetHostName();

            IPHostEntry ipEntry = System.Net.Dns.GetHostEntry(strHostName);

            IPAddress[] addr = ipEntry.AddressList;

            return addr[addr.Length - 1].ToString();
        }

        private void clientsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            ClientGrid.Visibility = Visibility.Visible;
            selectionText = clientsList.SelectedItem.ToString();
            VpnTunnel t = getVpnTunnelbySelection();
            if (t!=null)
            {
                icmpCheck.IsChecked = t.TransferIcmp;
                tcpCheck.IsChecked = t.TransferTcp;
            }
        }

        public VpnTunnel getVpnTunnelbySelection()
        {
            if (selectionText.Equals("no selection"))
                return null;
            string ip = selectionText.Substring(4, (selectionText.IndexOf("Mac:") - selectionText.IndexOf("Ip:") - 4));
            ipLabel.Content = ip;
            if (vpnTunnels.ContainsKey(ip.ToString()))
                return vpnTunnels[ip];
            return null;
        }


        private void policyIcmp1_Checked(object sender, RoutedEventArgs e)
        {
            if (ClientGrid.Visibility == Visibility.Visible)
            {
                VpnTunnel t = getVpnTunnelbySelection();
                if (t != null)
                    t.TransferIcmp = true;
            }
        }

        private void policyIcmp1_Unchecked(object sender, RoutedEventArgs e)
        {
            if (ClientGrid.Visibility == Visibility.Visible)
            {
                VpnTunnel t = getVpnTunnelbySelection();
                if (t != null)
                    t.TransferIcmp = false;
            }
        }

        private void policyTcp_Checked_1(object sender, RoutedEventArgs e)
        {
            if (ClientGrid.Visibility == Visibility.Visible)
            {
                VpnTunnel t = getVpnTunnelbySelection();
                if (t != null)
                    t.TransferTcp = true;
            }
        }

        private void policyTcp_Unchecked_1(object sender, RoutedEventArgs e)
        {
            if (ClientGrid.Visibility == Visibility.Visible)
            {
                VpnTunnel t = getVpnTunnelbySelection();
                if (t != null)
                    t.TransferTcp = false;
            }
        }

    }
}
