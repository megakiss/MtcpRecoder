using System.Net.NetworkInformation;
using System.Net.Sockets;

class Program
{
    const int MEGA_BYTE = (1024 * 1024);

    class MtcpClientSaveMessage
    {
        public long tickMillis;
        public byte[] data = Array.Empty<Byte>();
    }

    class MtcpClientSave
    {
        string strip = "";
        ushort port = 0;
        int nTotalByte = 0;
        string fileName = "";
        bool bRun = true;
        private Queue<MtcpClientSaveMessage> queue = new Queue<MtcpClientSaveMessage>();
        Thread? thread = null;
        public MtcpClientSave(string _strip, ushort _port)
        {
            strip = _strip;
            port = _port;
            fileName = DateTime.Now.ToString("yyMMdd_HHmm") + "_" + strip + "_" + port + ".pcap";
        }
        public void Send(long microseconds, byte[] data, int length)
        {

            byte[] outbuf = new byte[length];
            Array.Copy(data, outbuf, length);
            queue.Enqueue(new MtcpClientSaveMessage { tickMillis = microseconds, data = outbuf });
            if (thread == null)
            {
                thread = new Thread(Run);
                thread.Start();
            }
            //Console.WriteLine("q.send.Length:{0}", length);
        }
        private int GetPacket(List<Byte> data)
        {
            if (data.Count < 8) return 0;
            if (data[0] != 0xA0 || data[1] != 0xA0 || data[2] != 0xA0 || data[3] != 0xA0 || data[5] != 0) return -1;
            int mtcpLength = data[6] * 256 + data[7];
            return (data.Count < mtcpLength) ? 0 : mtcpLength;
        }

        public void Run()
        {
            Console.WriteLine("{0} record start", fileName);
            Stream fstream = new FileStream(fileName, FileMode.Create);
            using (BinaryWriter wr = new BinaryWriter(fstream))
            {
                List<Byte> byteAll = new List<byte>();
                bool bFirst = true;
                int nSaveMegaByte = 0;
                while (bRun)
                {
                    while (queue.Count > 0)
                    {
                        MtcpClientSaveMessage q = queue.Dequeue();
                        if (q == null) break;
                        foreach (byte b in q.data) byteAll.Add(b);
                        while (true)
                        {
                            int ret = GetPacket(byteAll);
                            if (ret == 0) break;
                            if (ret < 0)
                            {
                                byteAll.RemoveAt(0);
                                continue;
                            }
                            for (int i = 0; i < 8; i++) byteAll.RemoveAt(0);
                            Byte[] saveData = new byte[ret - 8];
                            for (int i = 0; i < saveData.Length; i++)
                            {
                                saveData[i] = byteAll[0];
                                byteAll.RemoveAt(0);
                            }
                            if (bFirst == true)
                            {
                                bFirst = false;
                                wr.Write(new byte[] { 0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00, 0x70, 0x81, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 });
                            }
                            uint ts_sec = (uint)(q.tickMillis / 1000000);
                            wr.Write(ts_sec);
                            uint ts_usec = (uint)(q.tickMillis % 1000000);
                            wr.Write(ts_usec);
                            uint incl_len = (uint)saveData.Length + 14;
                            wr.Write(incl_len);
                            wr.Write(incl_len);
                            wr.Write(new byte[] { 0x01, 0x00, 0x5e, 0x7f, 0x3a, 0x04, 0x00, 0x1e, 0x1b, 0x00, 0x00, 0x00, 0x08, 0x00 });
                            wr.Write(saveData);
                            nTotalByte += saveData.Length;
                            if (nSaveMegaByte != nTotalByte / MEGA_BYTE)
                            {
                                nSaveMegaByte = nTotalByte / MEGA_BYTE;
                                Console.WriteLine("SAVE {0} {1}", DateTime.Now, nSaveMegaByte);
                            }
                        }
                    }
                    Thread.Sleep(1);
                }
            }
            Console.WriteLine("{0} record end", fileName);
        }
        public void Release()
        {
            bRun = false;
            thread?.Join();
            thread = null;
        }
    }

    class MtcpClient
    {
        string strip = "";
        ushort port = 0;
        Thread? thread = null;
        public MtcpClient(string _strip, ushort _port)
        {
            strip = _strip;
            port = _port;
            thread = new Thread(Run);
            thread.Start();
        }
        public void Run()
        {
            Console.WriteLine("connect:{0}:{1}", strip, port);
            TcpClient? tc = null;
            MtcpClientSave? save = null;
            try
            {
                tc = new TcpClient(strip, port);
                tc.ReceiveBufferSize = MEGA_BYTE;
                int nTotalByte = 0;
                int nReceiveMegaByte = 0;
                while (nTotalByte < 500 * MEGA_BYTE)
                {
                    byte[] outbuf1 = new byte[MEGA_BYTE];
                    int nbytes1 = tc.GetStream().Read(outbuf1, 0, outbuf1.Length);
                    nTotalByte += nbytes1;
                    if (nReceiveMegaByte != nTotalByte / MEGA_BYTE)
                    {
                        nReceiveMegaByte = nTotalByte / MEGA_BYTE;
                        Console.WriteLine("RECEIVE {0} MByte", nReceiveMegaByte);
                    }
                    save ??= new MtcpClientSave(strip, port);
                    save.Send(DateTime.UtcNow.Ticks / 10, outbuf1, nbytes1);
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                tc?.GetStream()?.Close();
                tc?.Close();
            }
            save?.Release();
        }
        public void Release()
        {
            thread?.Join();
            thread = null;
        }
    }
    static void Main(string[] args)
    {
        List<MtcpClient> listThread = new();
        try
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
                foreach (GatewayIPAddressInformation address in adapter.GetIPProperties().GatewayAddresses)
                {
                    string gatewayIp = address.Address.ToString();
                    if (gatewayIp.Length >= 7)
                        for (int i = 0; i < 4; i++)
                            listThread.Add(new MtcpClient(gatewayIp, (ushort)(9800 + i)));
                }
        }
        catch (Exception)
        {
        }
        foreach (MtcpClient thread in listThread) thread.Release();
    }
}