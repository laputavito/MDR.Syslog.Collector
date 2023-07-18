package mdr.syslog.collector.main;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import mdr.syslog.collector.db.ConnectionPLDM;
import mdr.syslog.collector.util.CommonUtil;
import mdr.syslog.collector.util.Config;
import mdr.syslog.collector.util.Log;

public class MDRSyslogDemon {

	public static void main(String[] args) throws Exception {

		boolean isExec = false;
		String sDebug = "";
		isExec = true;
		int LocalPort = 514;
		
		if (!isExec) {
//			System.out.println("이전 배치 실행중.... 종료됨");
			Log.TraceLog("이전 배치 실행중.... - Done!!");
			System.exit(0);
		} else {
			Config.Status.isDebug = Boolean.parseBoolean(CommonUtil.getPropertiesInfo("isDebug"));
			LocalPort = Integer.parseInt(CommonUtil.getPropertiesInfo("LocalPort"));
			Config.Path.connectionPLDM = ConnectionPLDM.getPLDMInstance();
			
//			System.out.println("Aanlysis demon thread start.");
			Log.TraceLog("Syslog demon thread start.", "INFO");
			
//			if (args.length > 0){
//				if (!args[0].equals(null)){
//					Config.Status.sProcDate = args[0]; 
//				}
//			}else{
//				Config.Status.sProcDate = "";
//			}
			
			ArrayList<Thread> threadList = new ArrayList<Thread>();
			List<Runnable> threads = new ArrayList<Runnable>();

			BlockingQueue<String> pipe = new LinkedBlockingQueue();
	        SyslogListener listen = new SyslogListener(LocalPort, pipe);
	        SyslogObserver SD = new SyslogObserver();
	        
	        listen.addObserver(SD);

			threads.add(listen);

			for (Runnable th : threads) {
				Thread thread = new Thread(th);
				thread.start();
				threadList.add(thread);
			}

			for (Thread t : threadList) {
				t.join(); // 쓰레드의 처리가 끝날때까지 기다립니다.
			}

//			System.out.println("Aanlysis demon thread end.");
			Log.TraceLog("Aanlysis demon thread end.", "INFO");

		}
	}
}