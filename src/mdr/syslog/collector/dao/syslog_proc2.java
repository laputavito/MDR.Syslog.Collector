package mdr.syslog.collector.dao;

import java.net.DatagramPacket;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.Date;

import org.postgresql.PGConnection;

import mdr.syslog.collector.util.CommonUtil;
import mdr.syslog.collector.util.Config;
import mdr.syslog.collector.util.Log;

/**
 * 보안 관련  DB 로그수집 DAO
 * @author JINNEY
 *
 */
public class syslog_proc2 {
	private static Connection con = null;
	private static PGConnection pgcon = null;
	private static PreparedStatement pstmt = null;

	public static boolean syslog_proc2(DatagramPacket dat) throws Exception{
		try
		{
			//InputStream csvStr = null;
			con = Config.Path.connectionPLDM.getConnection();
  		    if(con == null){
				new Exception("DB Connection Error...!!");
			}

  		    //con.setAutoCommit(false);
            String load = new String(dat.getData(),0,dat.getLength());
            String append = new Date() +" [" + dat.getAddress().toString();
            String sIP = dat.getAddress().toString();
            append += "] " + load + "\n";
            append = append.trim();
            try {
				//syslog_proc.syslog_data_proc(sIP, load);
				Log.TraceLog(append, "INFO");
			} catch (Exception e1) {
				// TODO 자동 생성된 catch 블록
				e1.printStackTrace();
			}

            
  		    StringBuffer query = new StringBuffer();
			
			query = new StringBuffer();

			load = load.trim();
			sIP = sIP.replace("/", "");
			query.append(String.format("INSERT INTO syslog_data ( " +
					"log_time, ipaddress, msg) " +
				"values (now(), '%s', '%s' )", sIP, load));
			pstmt = (PreparedStatement) con.prepareStatement(query.toString());
			pstmt.executeUpdate();
			
			Config.Path.connectionPLDM.releaseConnection(con);

			return true;

		}catch(Exception e){
			e.printStackTrace();
			Log.TraceLog(e.toString(), "DEBUG");
			return false;
		}
	}
	
	@SuppressWarnings("deprecation")
	public static boolean syslog_data_proc2(String sIPAddress, String sMsg) throws Exception{
		try
		{

  		    //con.setAutoCommit(false);

  		    String output = sMsg;
	      	String[] textSplit = output.split("`",57);
	      	
	      	String isDebug = "";
	      	isDebug = CommonUtil.getPropertiesInfo("isDebug");
	      	String isTarget = "";
	      	isTarget = CommonUtil.getPropertiesInfo("isTarget");
	      	
	      	if (isDebug.equals("true"))
	      	{
	      		Log.TraceLog(sMsg, "DEBUG");
	      		System.out.println("Message : " + sMsg);
	      	}
	      	
	      	if (textSplit[0].indexOf("1001") <= 0)
	      	{
	      		return false;
	      	}
	      	
			PreparedStatement pstmt = null;
			
	      	String sldm_empno, sldm_ip, sldm_mac, sldm_org_logdate;
	      	String s_log_id, s_device_id, s_attacker_ip, s_event_id, s_severity, s_sensor_event_id, s_obj_type, s_my_id;
	      	String s_parent_id, s_detect_time, s_event_time, s_unknown, s_obj_name, s_md5, s_file_type, s_phase, s_vm_cnc_type;
	      	String s_detect_name, s_vt, s_target, s_proto, s_collect_method, s_attacker, s_direction, s_analysis_type;
	      	String s_file_category, s_action, s_total_anal_time, s_session, s_service_port, s_proxy_ip, s_source_ip;
	      	String s_file_size, s_pe_sign, s_crc64, s_attacker_domain, s_info_path, s_detect_category, s_snort_id;
	      	String s_cnc_type, s_auto_action, s_vm_used, s_ql_score, s_anal_from, s_anal_hostname, s_flow_type;
	      	String s_max_severity, s_malsite_type, s_related_event_id, s_related_obj_id, s_mail_msg_id, s_mail_hdr_from;
	      	String s_mail_hdr_to, s_api_type, s_client_id, s_vm_detect_name, s_vm_detect_user;
   	
	      	s_log_id = "1001";
	      	s_device_id = textSplit[1];
	      	s_attacker_ip = textSplit[2];
	      	s_event_id = textSplit[3];
	      	s_severity = textSplit[4];
	      	s_sensor_event_id = textSplit[5];
	      	s_obj_type = textSplit[6];
	      	s_my_id = textSplit[7];
	      	s_parent_id = textSplit[8];
	      	s_detect_time = textSplit[9];
	      	s_event_time = textSplit[10];
	      	s_unknown = textSplit[11];
	      	s_obj_name = textSplit[12];
	      	s_md5 = textSplit[13];
	      	s_file_type = textSplit[14];
	      	s_phase = textSplit[15];
	      	s_vm_cnc_type = textSplit[16];
	      	s_detect_name = textSplit[17];
	      	s_vt = textSplit[18];
	      	s_target = textSplit[19];
	      	s_proto = textSplit[20];
	      	s_collect_method = textSplit[21];
	      	s_attacker = textSplit[22];
	      	s_direction = textSplit[23];
	      	s_analysis_type = textSplit[24];
	      	s_file_category = textSplit[25];
	      	s_action = textSplit[26];
	      	s_total_anal_time = textSplit[27];
	      	s_session = textSplit[28];
	      	s_service_port = textSplit[29];
	      	s_proxy_ip = textSplit[30];
	      	s_source_ip = textSplit[31];
	      	s_file_size = textSplit[32];
	      	s_pe_sign = textSplit[33];
	      	s_crc64 = textSplit[34];
	      	s_attacker_domain = textSplit[35];
	      	s_info_path = textSplit[36];
	      	s_detect_category = textSplit[37];
	      	s_snort_id = textSplit[38];
	      	s_cnc_type = textSplit[39];
	      	s_auto_action = textSplit[40];
	      	s_vm_used = textSplit[41];
	      	s_ql_score = textSplit[42];
	      	s_anal_from = textSplit[43];
	      	s_anal_hostname = textSplit[44];
	      	s_flow_type = textSplit[45];
	      	s_max_severity = textSplit[46];
	      	s_malsite_type = textSplit[47];
	      	s_related_event_id = textSplit[48];
	      	s_related_obj_id = textSplit[49];
	      	s_mail_msg_id = textSplit[50];
	      	s_mail_hdr_from = textSplit[51];
	      	s_mail_hdr_to = textSplit[52];
	      	s_api_type = textSplit[53];
	      	s_client_id = textSplit[54];
	      	s_vm_detect_name = textSplit[55];
	      	s_vm_detect_user = textSplit[56];

	      	s_event_time = s_event_time.replace(".", " ");
	      	s_event_time = s_event_time.substring(0, 19);
	      	s_detect_time = s_detect_time.replace(".", " ");
	      	s_detect_time = s_detect_time.substring(0, 19);
	      	
			con = Config.Path.connectionPLDM.getConnection();
  		    if(con == null){
				new Exception("DB Connection Error...!!");
			}
  		    
	      	StringBuffer query = new StringBuffer();
			
      		String targetGroup[] = s_target.split(";");
      		int targetCnt = 0;
      		targetCnt = targetGroup.length;
      		
      		for(int i = 0;i < targetCnt; i++)
      		{
	      		String tar1 = targetGroup[i];
	      		
		      	query = new StringBuffer();
		      	
		      	if (isTarget.equals("IP"))
		      	{
		      		query.append("select sldm_empno, sldm_mac, sldm_ip from user_mstr where user_mstr.sldm_ip = '" + tar1 + "';");
		      	}
		      	else
		      	{
		      		query.append("select sldm_empno, sldm_mac, sldm_ip from user_mstr where user_mstr.sldm_email = '" + tar1 + "';");
		      	}
		      	
				pstmt = con.prepareStatement(query.toString());
				
				ResultSet rs = pstmt.executeQuery();

				sldm_empno = "";
				sldm_mac = "";
				sldm_ip = "";
				
				
				while(rs.next()){
					sldm_empno = rs.getString(1);
					sldm_mac = rs.getString(2);
					sldm_ip = rs.getString(3);
				}
				
				if (sldm_empno.equals("")) 
				{
					continue;
				}
				
		      	sldm_org_logdate = s_event_time;


			    query = new StringBuffer();

			    query.append(String.format("INSERT INTO apt_search_engine_log (sldm_empno, sldm_ip, sldm_mac, sldm_org_logdate, " +
  		    		        "log_id, device_id, attacker_ip, event_id, severity, sensor_event_id, obj_type, " +
			    		    "my_id, parent_id, detect_time, event_time, unknown, obj_name, md5, file_type, phase, " +
							"vm_cnc_type, detect_name, vt, target, proto, collect_method, attacker, direction, " +
							"analysis_type, file_category, action, total_anal_time, session, service_port, " +
							"proxy_ip, source_ip, file_size, pe_sign, crc64, attacker_domain, info_path, detect_category, " +
							"snort_id, cnc_type, auto_action, vm_used, ql_score, anal_from, anal_hostname, flow_type, " +
							"max_severity, malsite_type, related_event_id, related_obj_id, mail_msg_id, mail_hdr_from, " +
							"mail_hdr_to, api_type, client_id, vm_detect_name, vm_detect_user) " +
							"VALUES('%s', '%s', '%s', '%s', " +
							"'%s', '%s', '%s', '%s', '%s', '%s', '%s', " +
							"'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " + 
							"'%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', " + 
							"'%s', '%s', '%s', %s, '%s', %s, " + 
							"'%s', '%s', %s, '%s', '%s', '%s', '%s', '%s', " + 
							"%s, '%s', '%s', '%s', %s, '%s', '%s', '%s', " + 
							"'%s', '%s', '%s', %s, '%s', '%s', " + 
							"'%s', '%s', '%s', '%s', '%s');",
							sldm_empno, sldm_ip, sldm_mac, sldm_org_logdate, s_log_id, s_device_id, s_attacker_ip, s_event_id, s_severity, s_sensor_event_id, s_obj_type, s_my_id,
							s_parent_id, s_detect_time, s_event_time, s_unknown, s_obj_name, s_md5, s_file_type, s_phase, s_vm_cnc_type,
							s_detect_name, s_vt, tar1, s_proto, s_collect_method, s_attacker, s_direction, s_analysis_type,
							s_file_category, s_action, s_total_anal_time, s_session, s_service_port, s_proxy_ip, s_source_ip,
							s_file_size, s_pe_sign, s_crc64, s_attacker_domain, s_info_path, s_detect_category, s_snort_id,
							s_cnc_type, s_auto_action, s_vm_used, s_ql_score, s_anal_from, s_anal_hostname, s_flow_type,
							s_max_severity, s_malsite_type, s_related_event_id, s_related_obj_id, s_mail_msg_id, s_mail_hdr_from,
							s_mail_hdr_to, s_api_type, s_client_id, s_vm_detect_name, s_vm_detect_user));
							

			    
				pstmt = (PreparedStatement)con.prepareStatement(query.toString());


				pstmt.executeUpdate();
				pstmt.clearParameters();
      		}
		
			Config.Path.connectionPLDM.releaseConnection(con);

			return true;

		}catch(Exception e){
			e.printStackTrace();
			Log.TraceLog(e.toString(), "DEBUG");
			return false;
		}
	}
}
