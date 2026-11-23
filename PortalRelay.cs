using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;

// This process is launched by the ordinary desktop UI, never by the elevated guard.
class PortalRelay {
    static string settings, log;
    static int index;
    static IPAddress source, dns;
    static readonly object gate = new object();
    static void Note(string kind,string host) {
        lock(gate) File.AppendAllText(log, DateTime.Now.ToString("HH:mm:ss")+" "+kind+" "+host+"\n");
    }
    static string Line(Stream s) {
        var bytes=new List<byte>();
        while(bytes.Count<8192) {
            int b=s.ReadByte(); if(b<0) throw new EndOfStreamException();
            if(b==10) return Encoding.ASCII.GetString(bytes.ToArray()).TrimEnd('\r');
            bytes.Add((byte)b);
        }
        throw new IOException("header");
    }
    static void Send(Stream s,string text) {
        var b=Encoding.ASCII.GetBytes(text); s.Write(b,0,b.Length);
    }
    static void Bind(Socket s) {
        s.SetSocketOption(SocketOptionLevel.IP,(SocketOptionName)31,IPAddress.HostToNetworkOrder(index));
        s.Bind(new IPEndPoint(source,0));
    }
    static int Word(byte[] b,int p) { return b[p]*256+b[p+1]; }
    static void Skip(byte[] b,ref int p) {
        while(true) {int n=b[p++]; if(n==0)return;
            if((n&192)==192){p++;return;} if(n>63)throw new IOException("DNS");
            p+=n;
        }
    }
    static IPAddress Resolve(string host) {
        IPAddress ip;
        if(IPAddress.TryParse(host,out ip))return ip;
        byte[] id=new byte[2]; using(var rng=RandomNumberGenerator.Create()) rng.GetBytes(id);
        var q=new List<byte>(new byte[]{id[0],id[1],1,0,0,1,0,0,0,0,0,0});
        foreach(var label in host.Split('.')) {
            var l=Encoding.ASCII.GetBytes(label); if(l.Length<1||l.Length>63)throw new IOException("DNS label");
            q.Add((byte)l.Length);q.AddRange(l);
        }
        q.AddRange(new byte[]{0,0,1,0,1});
        using(var u=new UdpClient(AddressFamily.InterNetwork)){
            Bind(u.Client);u.Client.ReceiveTimeout=2500;u.Connect(dns,53);
            u.Send(q.ToArray(),q.Count);IPEndPoint from=null;byte[] b=u.Receive(ref from);
            if(b.Length<12||b[0]!=id[0]||b[1]!=id[1]||(b[2]&128)==0||(b[3]&15)!=0||Word(b,4)!=1)throw new IOException("DNS reply");
            int p=12;Skip(b,ref p);p+=4;
            for(int i=0;i<Word(b,6);i++){Skip(b,ref p);int type=Word(b,p),cls=Word(b,p+2),n=Word(b,p+8);p+=10;
                if(type==1&&cls==1&&n==4)return new IPAddress(new byte[]{b[p],b[p+1],b[p+2],b[p+3]});p+=n;}
        }
        throw new IOException("No IPv4 address");
    }
    static bool Allowed(string host) {
        try { return File.ReadAllLines(settings).Contains(host) && File.ReadAllLines(settings+".enabled").Contains(host); }
        catch(IOException) { return false; }
    }
    static void Serve(TcpClient client) {
        using(client) try {
            client.ReceiveTimeout=8000;var input=client.GetStream();string[] first=Line(input).Split(' ');
            if(first.Length!=3)return;
            bool tunnel=first[0]=="CONNECT";
            Uri uri=new Uri(tunnel?"https://"+first[1]:first[1]);
            string host=uri.IdnHost.ToLowerInvariant().TrimEnd('.');
            var headers=new List<string>();int length=0;
            for(int i=0;;i++){string h=Line(input);if(h=="")break;if(i>100)return;
                int pos=h.IndexOf(':');if(pos<1)return;
                string k=h.Substring(0,pos).ToLowerInvariant(),v=h.Substring(pos+1).Trim();
                if(k=="transfer-encoding")return;
                if(k=="content-length"&&(!int.TryParse(v,out length)||length<0||length>8*1024*1024))return;
                if(k!="host"&&k!="connection"&&!k.StartsWith("proxy-"))headers.Add(h);
            }
            if(!Allowed(host)||uri.UserInfo.Length!=0||
                (tunnel?uri.Port!=443:(uri.Scheme!="http"||uri.Port!=80))){
                Note("BLOCK",host);Send(input,"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");return;
            }
            Note("REQUEST",host);
            IPAddress ip=Resolve(host);byte top=ip.GetAddressBytes()[0];
            if(ip.AddressFamily!=AddressFamily.InterNetwork||IPAddress.IsLoopback(ip)||ip.Equals(source)||top==0||top>=224)return;
            // Request a destination-specific WFP permit and wait for its transaction.
            lock(gate) File.AppendAllText(settings+".pins",host+" "+ip+" "+uri.Port+"\n");
            bool approved=false;
            for(int i=0;i<120;i++){
                if(!Allowed(host))return;
                try{approved=File.ReadAllLines(settings+".ack").Contains(ip+" "+uri.Port);}catch(IOException){}
                if(approved)break;
                Thread.Sleep(100);
            }
            if(!approved){Note("WAIT",host);return;}
            using(var remote=new TcpClient(AddressFamily.InterNetwork))
            using(var revoke=new Timer(s=>{
                if(!Allowed(host)){ client.Close(); remote.Close(); }
            },null,0,150)){
                if(!Allowed(host))return;
                Bind(remote.Client);
                if(!remote.ConnectAsync(ip,uri.Port).Wait(5000))return;
                var upstream=remote.GetStream();Note("ALLOW",host);
                if(tunnel){Send(input,"HTTP/1.1 200 Connection Established\r\n\r\n");
                    Task.WaitAny(input.CopyToAsync(upstream),upstream.CopyToAsync(input));}
                else {
                    Send(upstream,first[0]+" "+uri.PathAndQuery+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n"+String.Join("\r\n",headers)+(headers.Count>0?"\r\n":"")+"\r\n");
                    byte[] buf=new byte[8192];while(length>0){int n=input.Read(buf,0,Math.Min(length,buf.Length));if(n==0)return;upstream.Write(buf,0,n);length-=n;}
                    upstream.CopyTo(input);
                }
            }
        } catch(Exception) { }
    }
    static int Main(string[] a){
        settings=a[0];log=a[1];source=IPAddress.Parse(a[2]);dns=IPAddress.Parse(a[3]);index=int.Parse(a[4]);
        var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
        Console.WriteLine(((IPEndPoint)listener.LocalEndpoint).Port);Console.Out.Flush();
        // EOF from the UI, network changes, and expiry terminate all established tunnels.
        new Thread(()=>{Console.ReadLine();Environment.Exit(0);}){IsBackground=true}.Start();
        System.Net.NetworkInformation.NetworkChange.NetworkAddressChanged+=(s,e)=>Environment.Exit(0);
        var timer=new Timer(s=>Environment.Exit(0),null,TimeSpan.FromMinutes(10),TimeSpan.FromMilliseconds(-1));
        while(true){var client=listener.AcceptTcpClient();Task.Run(()=>Serve(client));GC.KeepAlive(timer);}
    }
}
