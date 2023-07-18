package mdr.syslog.collector.main;
import java.net.DatagramPacket;
import java.util.Date;
import java.util.Observable;
import java.util.Observer;

import mdr.syslog.collector.dao.syslog_proc;
import mdr.syslog.collector.dao.syslog_proc2;
import mdr.syslog.collector.db.ConnectionPLDM;
import mdr.syslog.collector.util.CommonUtil;
import mdr.syslog.collector.util.Config;
import mdr.syslog.collector.util.Log;

public class SyslogObserver implements Observer {
	private boolean isRun = true;
	private boolean isCollect = true;
	private String logFilePathFullName = Config.Path.LogFilePath;

    @Override
    public void update(Observable o, Object arg) {
    	try {
	        if (arg instanceof String){
	            //mainTextArea.append((String) arg + "\n");
	        }
	        else if (arg instanceof DatagramPacket){
	            DatagramPacket dat = (DatagramPacket)arg;            
	            String load = new String(dat.getData(),0,dat.getLength());
	            String append = new Date() +" [" + dat.getAddress().toString();
	            String sIP = dat.getAddress().toString();
	            append += "] " + load + "\n";
	            append = append.trim();
	            try {
	            	
	    	      	String LogType = "";
	    	      	LogType = CommonUtil.getPropertiesInfo("LogType");
	    	      	
	    	      	if (LogType.equals("EVENT"))
	    	      	{
						syslog_proc.syslog_data_proc(sIP, load);
	    	      	}
	    	      	else
	    	      	{
						syslog_proc2.syslog_data_proc2(sIP, load);
	    	      	}
	    	      	

					//Log.TraceLog(append, "INFO");
				} catch (Exception e1) {
					// TODO 자동 생성된 catch 블록
					e1.printStackTrace();
				}
	
	            //mainTextArea.append(append);
	        }
    	} catch (Exception ex) {
    		ex.printStackTrace();
    	}
    	
    }
}