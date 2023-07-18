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
public class syslog_proc {
	private static Connection con = null;
	private static PGConnection pgcon = null;
	private static PreparedStatement pstmt = null;

	public static boolean syslog_proc(DatagramPacket dat) throws Exception{
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
	public static boolean syslog_data_proc(String sIPAddress, String sMsg) throws Exception{
		try
		{

  		    //con.setAutoCommit(false);

  		    String output = sMsg;
	      	String[] textSplit = output.split("\\|");
  		    

	      	
	      	String isDebug = "";
	      	isDebug = CommonUtil.getPropertiesInfo("isDebug");
	      	String isTarget = "";
	      	isTarget = CommonUtil.getPropertiesInfo("isTarget");
	      	
	      	if (isDebug.equals("true"))
	      	{
	      		Log.TraceLog(sMsg, "DEBUG");
	      		System.out.println("Message : " + sMsg);
	      	}
	      	
	      	if (!textSplit[4].equals("event"))
	      	{
	      		return false;
	      	}
	      	
			PreparedStatement pstmt = null;
			
	      	String sldm_empno, sldm_ip, sldm_mac, sldm_org_logdate;
	      	String s_device_id, s_sensor_event_id, s_attacker, s_attacker_domain, s_attacker_ip, s_target;
	      	String s_direction, s_session, s_obj_type, s_phase, s_collect_method, s_proto, s_service_port;
	      	String s_action, s_proxy_ip, s_event_time, s_related_event_id, s_related_obj_id, s_info_path;
	      	String s_source_ip, s_event_id, s_flow_type, s_max_severity, s_mail_msg_id, s_mail_hdr_from, s_mail_hdr_to, s_api_type;
	      	String apt_event_log = textSplit[6];
	      	String[] event_data = apt_event_log.split(",");
	      	
	      	String[] device_id = event_data[0].split("=");
	      	if(device_id.length <= 1) s_device_id = ""; else s_device_id = device_id[1];
	      	String[] sensor_event_id = event_data[1].split("=");
	      	if(sensor_event_id.length <= 1) s_sensor_event_id = ""; else s_sensor_event_id = sensor_event_id[1];
	      	String[] attacker = event_data[2].split("=");
	      	if(attacker.length <= 1) s_attacker = ""; else s_attacker = attacker[1];
	      	String[] attacker_domain = event_data[3].split("=");
	      	if(attacker_domain.length <= 1) s_attacker_domain = ""; else s_attacker_domain = attacker_domain[1];
	      	String[] attacker_ip = event_data[4].split("=");
	      	if(attacker_ip.length <= 1) s_attacker_ip = ""; else s_attacker_ip = attacker_ip[1];
	      	String[] target = event_data[5].split("=");
	      	if(target.length <= 1) s_target = ""; else s_target = target[1];
	      	String[] direction = event_data[6].split("=");
	      	if(direction.length <= 1)  s_direction = ""; else s_direction = direction[1];
	      	String[] session = event_data[7].split("=");
	      	if(session.length <= 1)  s_session = ""; else s_session = session[1];
	      	String[] obj_type = event_data[8].split("=");
	      	if(obj_type.length <= 1)  s_obj_type = ""; else s_obj_type = obj_type[1];
	      	String[] phase = event_data[9].split("=");
	      	if(phase.length <= 1)  s_phase = ""; else s_phase = phase[1];
	      	String[] collect_method = event_data[10].split("=");
	      	if(collect_method.length <= 1)  s_collect_method = ""; else s_collect_method = collect_method[1];
	      	String[] proto = event_data[11].split("=");
	      	if(proto.length <= 1)  s_proto = ""; else s_proto = proto[1];
	      	String[] service_port = event_data[12].split("=");
	      	if(service_port.length <= 1)  s_service_port = "0"; else s_service_port = service_port[1];
	      	String[] action = event_data[13].split("=");
	      	if(action.length <= 1)  s_action = ""; else s_action = action[1];
	      	String[] proxy_ip = event_data[14].split("=");
	      	if(proxy_ip.length <= 1)  s_proxy_ip = ""; else s_proxy_ip = proxy_ip[1];
	      	String[] event_time = event_data[15].split("=");
	      	if(event_time.length <= 1)  s_event_time = ""; else s_event_time = event_time[1];
	      	String[] related_event_id = event_data[16].split("=");
	      	if(related_event_id.length <= 1)  s_related_event_id = ""; else s_related_event_id = related_event_id[1];
	      	String[] related_obj_id = event_data[17].split("=");
	      	if(related_obj_id.length <= 1)  s_related_obj_id = "0"; else s_related_obj_id = related_obj_id[1];
	      	String[] info_path = event_data[18].split("=");
	      	if(info_path.length <= 1)  s_info_path = ""; else s_info_path = info_path[1];
	      	String[] source_ip = event_data[19].split("=");
	      	if(source_ip.length <= 1)  s_source_ip = ""; else s_source_ip = source_ip[1];
	      	String[] event_id = event_data[20].split("=");
	      	if(event_id.length <= 1)  s_event_id = ""; else s_event_id = event_id[1];
	      	String[] flow_type = event_data[21].split("=");
	      	if(flow_type.length <= 1)  s_flow_type = ""; else s_flow_type = flow_type[1];
	      	String[] max_severity = event_data[22].split("=");
	      	if(max_severity.length <= 1)  s_max_severity = ""; else s_max_severity = max_severity[1];
	      	String[] mail_msg_id = event_data[23].split("=");
	      	if(mail_msg_id.length <= 1)  s_mail_msg_id = ""; else s_mail_msg_id = mail_msg_id[1];
	      	String[] mail_hdr_from = event_data[24].split("=");
	      	if(mail_hdr_from.length <= 1)  s_mail_hdr_from = ""; else s_mail_hdr_from = mail_hdr_from[1];
	      	String[] mail_hdr_to = event_data[25].split("=");
	      	if(mail_hdr_to.length <= 1)  s_mail_hdr_to = ""; else s_mail_hdr_to = mail_hdr_to[1];
	      	String[] api_type = event_data[26].split("=");
	      	if(api_type.length <= 1)  s_api_type = "0"; else s_api_type = api_type[1];

	      	s_event_time = s_event_time.replace(".", " ");
	      	s_event_time = s_event_time.substring(0, 19);
	      	
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

			    query.append(String.format("INSERT INTO apt_event_log (sldm_empno, sldm_ip, sldm_mac, sldm_org_logdate, device_id, sensor_event_id, attacker, attacker_domain, attacker_ip, target, " +
							"direction, session, obj_type, phase, collect_method, proto, service_port, " +
							"action, proxy_ip, event_time, related_event_id, related_obj_id, info_path, " +
							"source_ip, event_id, flow_type, max_severity, mail_msg_id, mail_hdr_from, mail_hdr_to, api_type) " +
							"VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %s, '%s', '%s', '%s'," + 
							"'%s', %s, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %s);", 
							sldm_empno, sldm_ip, sldm_mac, sldm_org_logdate, s_device_id, s_sensor_event_id, s_attacker, s_attacker_domain, s_attacker_ip, tar1,
							s_direction, s_session, s_obj_type, s_phase, s_collect_method, s_proto, s_service_port,
							s_action, s_proxy_ip, s_event_time, s_related_event_id, s_related_obj_id, s_info_path,
							s_source_ip, s_event_id, s_flow_type, s_max_severity, s_mail_msg_id, s_mail_hdr_from, s_mail_hdr_to, s_api_type));

			    
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
