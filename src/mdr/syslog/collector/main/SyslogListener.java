package mdr.syslog.collector.main;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.util.Observable;
import java.util.concurrent.BlockingQueue;

import mdr.syslog.collector.dao.syslog_proc;
import mdr.syslog.collector.util.Log;

public class SyslogListener extends Observable implements Runnable{
    private int localport;
    private volatile boolean running;
    private BlockingQueue<String> queue;
    private DatagramSocket socket;

    public int getLocalport() {
        return localport;
    }
    
    public String getLocalportString() {
        return ""+localport;
    }
    
    public void closeSocket(){
        if(!this.socket.isClosed()){
            this.socket.close();
        }
    }

    public boolean isRunning() {
        return running;
    }

    public void setRunning(boolean running) {
        this.running = running;
    }

    public SyslogListener(int localport,BlockingQueue<String> queue){
        this.localport = localport;
        this.queue = queue;
        this.running = true;           
    }

    public SyslogListener(BlockingQueue<String> queue) throws SocketException {
        this(514,queue);
    }
    
    @Override
    public void run() {
        try {      
            this.socket = new DatagramSocket(this.localport);
            while(this.running){
                DatagramPacket data = new DatagramPacket(new byte[4096], 4096);
                socket.receive(data);
                setChanged();
                notifyObservers(data);
            }
            
        } catch (SocketException ex) {
            System.out.println(ex.toString());
        } catch (IOException ex) {
            System.out.println(ex.toString());
        } catch (Exception e) {
			// TODO 자동 생성된 catch 블록
			e.printStackTrace();
		} finally {
            this.socket.close();
        }
    }
    
}
