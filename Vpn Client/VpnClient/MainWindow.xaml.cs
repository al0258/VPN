using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using PcapDotNet.Packets;
using PcapDotNet.Packets.IpV4;
using System.Net;
using System.Net.NetworkInformation;
using System.Collections;

namespace VpnClient
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private static VpnTunnel t1;
        public static ListBox packetLst;
        public static ListBox serverComputersLst;
        public static CheckBox fullModeCheck;
        string localIpAddr;
        public static string localMacAddr;
        public static string serverIp;

        private void ConnectBT_Click_1(object sender, RoutedEventArgs e)
        {//Click on the connect button - starts the vpn tunnel between the client and the server
            packetLst = packetListBox;
            serverComputersLst = serverComputersListBox;
            fullModeCheck = fullmodeCheckBox;
            serverIp = ipTXT.Text;
            localIpAddr = GetLocalIPAddress();
            localMacAddr = GetLocalMacAddress();
            //Creating the VpnTunnel Object with ip,port,password
            t1 = new VpnTunnel(serverIp, 4466, passTXT.Text);
            t1.CreateTunnel();
            if (t1.SendAuthentication())
            {//Checking Authentication
                foreach (DictionaryEntry entry in t1.ServerComputersTable)
                {//Writing the computers of the server on the listbox
                    Application.Current.Dispatcher.Invoke(new Action(() => {MainWindow.serverComputersLst.Items.Add("Ip: " + entry.Key.ToString() + " Mac: " + entry.Value.ToString()); }));
                }
                Thread sniffSender = new Thread(SniffAndSendToServer);
                sniffSender.Start();//Starting the PacketSniffer and SendToServer Thread
                Thread receiver = new Thread(ReceiveFromServer);
                receiver.Start();//Starting the Reciever from server Thread

                //Open the client window, close the Connect window
                ConnectGrid.Visibility = Visibility.Hidden;
                ConnectGrid.IsEnabled = false;
                ClientGrid.Visibility = Visibility.Visible;
                ClientGrid.IsEnabled = true;
            }
            else
            {//Authentication Faild - Close connection with the server
                t1.CloseConnection();
            }
        }

        public static void SniffAndSendToServer()
        {
            PacketSniffer ps = new PacketSniffer();//Creating the sniffing object
            for (;;) //Loop that scanning for packets from the client describe the packet and send to server
            {
                Console.WriteLine("Scanning for packets..");
                Packet packet = ps.CapturePacket();//Getting the Sniffed packet
                IpV4Datagram ipV4 = packet.Ethernet.IpV4;//Getting the ipv4 layer of the packet
                if (ipV4.Source.ToString().Equals(GetLocalIPAddress()) && (t1.Connected) &&
                    !ipV4.Destination.ToString().Equals(serverIp) && !ipV4.Source.ToString().Equals(serverIp))
                {/*Checking if the packet source is your source, vpntunnel is connected,
                    packet destination and source isn't server ip*/
                    string packetProtocol = "";
                    switch (ipV4.Protocol)
                    {//Checking the packet protocol(Icmp/Tcp/Udp)
                        case IpV4Protocol.InternetControlMessageProtocol://ICMP Packet
                            packetProtocol = "Icmp";
                            break;

                        case IpV4Protocol.Tcp://TCP Packet
                            packetProtocol = "Tcp";
                            break;

                        case IpV4Protocol.Udp://UDP Packet
                            packetProtocol = "UDP";
                            break;
                    }
                    
                    if (t1.ServerComputersTable.ContainsKey(ipV4.Destination.ToString()))
                    {//Checking if the packet ip destination is one of the server computers ip 
                        Application.Current.Dispatcher.Invoke(new Action(() =>
                        {//Writing the packet information on the packet transport listbox
                            MainWindow.packetLst.Items.Add(packetProtocol + "Request: "
                                + ipV4.Source.ToString() + "==>" + ipV4.Destination.ToString());
                        }));
                            
                        t1.SendData(packet.Buffer);//Sending the packet to the server
                    }

                }
            }
        }

        public static void ReceiveFromServer()
        {
            for (;;)
            {//Loop that waiting on port to receive data from the server and give it to the computer as a packet
                try
                {
                    byte[] data = t1.ReceiveData();//Waiting for data and receivig it
                    Packet packet = new Packet(data, DateTime.Now, DataLinkKind.IpV4);//Building packet from the data
                    Console.WriteLine(">>>>>>>>>>>>Reply Found: " + packet.Ethernet.IpV4.Source);
                    IpV4Datagram ipV4 = packet.Ethernet.IpV4;//Getting the ipv4 layer of the packet
                    if (!ipV4.Destination.ToString().Equals(serverIp) && !ipV4.Source.ToString().Equals(serverIp))
                    {//Checking if the packet destination isn't the server and the packet source isn't the server
                        Application.Current.Dispatcher.Invoke(new Action(() => {//Writing the packet information
                            MainWindow.packetLst.Items.Add("Reply:   " + ipV4.Destination.ToString() +
                                "<==" + ipV4.Source.ToString());
                        }));
                        PacketSniffer ps = new PacketSniffer();
                        ps.SendPacket(packet);//Entering the packet into the computer
                    }
                }
                catch
                {//Exception with the socket - Closing the connection/the vpn tunnel
                    t1.CloseConnection();
                    t1.CreateTunnel();
                    Console.WriteLine("Connection lost");
                }
            }
        }

        private void disconnectBT_Click_1(object sender, RoutedEventArgs e)
        {
            //Close the connection, Open the client window, close the Connect window
            t1.CloseConnection();
            ConnectGrid.Visibility = Visibility.Visible;
            ConnectGrid.IsEnabled = true;
            ClientGrid.Visibility = Visibility.Hidden;
            ClientGrid.IsEnabled = false;
        }

        public static string GetLocalIPAddress()
        {//Function that returns the Local Ip Address of the computer
            string strHostName = "";
            strHostName = System.Net.Dns.GetHostName();

            IPHostEntry ipEntry = System.Net.Dns.GetHostEntry(strHostName);

            IPAddress[] addr = ipEntry.AddressList;

            return addr[addr.Length - 1].ToString();
        }

        public static string GetLocalMacAddress()
        {//Function that returs the Local Mac Address of the computer
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            String sMacAddress = string.Empty;
            foreach (NetworkInterface adapter in nics)
            {
                if (sMacAddress == String.Empty)
                {
                    IPInterfaceProperties properties = adapter.GetIPProperties();
                    sMacAddress = adapter.GetPhysicalAddress().ToString();
                }
            } return sMacAddress;
        }

        private void sendPingBT_Click(object sender, RoutedEventArgs e)
        {//Function that sending ping to chosen computer on the vpn
            Ping pingSender = new Ping();
            string[] split = serverComputersListBox.SelectedItem.ToString().Split(' ');
            PingReply reply = pingSender.Send(split[1]);
            if (reply.Status == IPStatus.Success)
            {
                Console.WriteLine("Address: {0}", reply.Address.ToString());
                Console.WriteLine("RoundTrip time: {0}", reply.RoundtripTime);
                Console.WriteLine("Time to live: {0}", reply.Options.Ttl);
                Console.WriteLine("Don't fragment: {0}", reply.Options.DontFragment);
                Console.WriteLine("Buffer size: {0}", reply.Buffer.Length);
            }
            else
            {
                Console.WriteLine(reply.Status);
            }
        }

        private void serverComputersListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {//When item on the computersListBox Selected - open the ping send button
            sendPingBT.Visibility = Visibility.Visible;
            string[] split = serverComputersListBox.SelectedItem.ToString().Split(' ');
            sendPingBT.Content = "Ping " + split[1];
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}
