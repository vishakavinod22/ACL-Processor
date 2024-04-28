package org.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class ExtendedACLProcessor {
    public static void main(String[] args) throws IOException {

        //Read the Extended ACL file for ACL 1
        String ACLFile1 = "src/main/resources/Extended/ExtendedACLStatement1.txt";
        HashMap<Integer, String> ACLList1 = readACL(ACLFile1);
        System.out.println(ACLList1);
        // Reads the ip address list for extended ACL 1
        String ipFile1 = "src/main/resources/Extended/IPAddressList1.txt";
        List<String> IPList1 = readIpList(ipFile1);
        // Validates each ip address with the ACL statements
        System.out.println("Sample 1: Extended ACL Output 1".toUpperCase());
        for(String ip : IPList1){
            validateACL(ACLList1, ip);
        }
        System.out.println();

        //Read the Extended ACL file for ACL 2
        String ACLFile2 = "src/main/resources/Extended/ExtendedACLStatement2.txt";
        HashMap<Integer, String> ACLList2 = readACL(ACLFile2);
        // Reads the ip address list for extended ACL 2
        String ipFile2 = "src/main/resources/Extended/IPAddressList2.txt";
        List<String> IPList2 = readIpList(ipFile2);
        // Validates each ip address with the ACL statements
        System.out.println("Sample 2: Extended ACL Output 2".toUpperCase());
        for(String ip : IPList2){
            validateACL(ACLList2, ip);
        }
        System.out.println();

        //Read the Extended ACL file for ACL 3
        String ACLFile3 = "src/main/resources/Extended/ExtendedACLStatement3.txt";
        HashMap<Integer, String> ACLList3 = readACL(ACLFile3);
        // Reads the ip address list for extended ACL 3
        String ipFile3 = "src/main/resources/Extended/IPAddressList3.txt";
        List<String> IPList3 = readIpList(ipFile3);
        // Validates each ip address with the ACL statements
        System.out.println("Sample 3: Extended ACL Output 3".toUpperCase());
        for(String ip : IPList3){
            validateACL(ACLList3, ip);
        }
        System.out.println();

        //Read the Extended ACL file for ACL 4
        String ACLFile4 = "src/main/resources/Extended/ExtendedACLStatement4.txt";
        HashMap<Integer, String> ACLList4 = readACL(ACLFile4);
        // Reads the ip address list for extended ACL 4
        String ipFile4 = "src/main/resources/Extended/IPAddressList4.txt";
        List<String> IPList4 = readIpList(ipFile4);
        // Validates each ip address with the ACL statements
        System.out.println("Sample 4: Extended ACL Output 4".toUpperCase());
        for(String ip : IPList4){
            validateACL(ACLList4, ip);
        }
        System.out.println();
    }

    // Private method to read the standard ACL file
    private static HashMap<Integer, String> readACL(String fileName) throws IOException{
        HashMap<Integer, String> ipList = new HashMap<>();
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        int cnt = 0;
        while((line = reader.readLine()) != null){
            if (line.startsWith("access-list")){
                String[] acl = line.split(" ");
                String finalACL;
                String[] srcIp = {"0","0","0","0"};//acl[4].split("\\.");
                String[] srcMask = {"255","255","255","255"}; //acl[5].split("\\.");
                String[] destIp = {"0","0","0","0"}; //acl[6].split("\\.");
                String[] destMask = {"255","255","255","255"}; //acl[7].split("\\.");

                if(!acl[4].equals("any")){
                    srcIp = acl[4].split("\\.");
                    srcMask = acl[5].split("\\.");
                }

                if(!acl[5].equals("any")){
                    destIp = acl[6].split("\\.");
                    destMask = acl[7].split("\\.");
                }

                // Updates the ip address based on the masks
                for(int i=0; i<4; i++){
                    if(srcMask[i].equals("255")){
                        srcIp[i] = "0";
                    }
                    if(destMask[i].equals("255")){
                        destIp[i] = "0";
                    }
                }

                // Formats the updated address into a string
                String srcIP = Arrays.toString(srcIp).replaceAll("[\\[\\]\"]","").replaceAll(", ",".");
                String destIP = Arrays.toString(destIp).replaceAll("[\\[\\]\"]","").replaceAll(", ",".");

                // Separates the ACL string based on the protocol
                // Adds the ACL details to the Hashmap in the format protocol_permission_src_srcIpAddr_dest_destIpAddr_eq_portNumber
                // If the first ACL statement is "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 range 20-21"
                        // then the hashmap is 0=tcp_deny_src_172.16.0.0_dest_172.16.3.0_range_20-21
                if(acl[3].equals("ip")){
                    finalACL = "ip_"+acl[2]+"_src_"+srcIP+"_dest_"+destIP;
                } else {
                    finalACL = acl[3]+"_"+acl[2]+"_src_"+srcIP+"_dest_"+destIP+"_"+acl[8]+"_"+acl[9];
                }

                ipList.put(cnt, finalACL);
            }
            cnt+=1;
        }
        reader.close();
        return ipList;
    }

    // Private method to read the IP Address file for standard ACL
    private static List<String> readIpList(String fileName) throws IOException {
        String line;
        List<String> IPList = new ArrayList<>();
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        while ((line = reader.readLine()) != null) {
            String ipAddrList = line.replaceAll(" ","_");
            IPList.add(ipAddrList);
        }
        reader.close();
        return IPList;
    }

    // Method to validate the IP address based on the given ACL
    private static void validateACL(HashMap<Integer, String> ACLList, String ip){
        String[] AclRule, srcIP, destIP, port, inputSrcIP, inputDestIP;
        String protocol, permission, inputPort;
        boolean res;
        int i = 0;

        String[] inputIP = ip.split("_");

        while(i<ACLList.size()){
            // Input IP Details
            inputSrcIP = inputIP[0].split("\\.");
            inputDestIP = inputIP[1].split("\\.");
            inputPort = inputIP[2];

            // ACL List Details
            AclRule = ACLList.get(i).split("_");
            protocol = AclRule[0];
            permission = AclRule[1];
            srcIP = AclRule[3].split("\\.");
            destIP = AclRule[5].split("\\.");

            // Assigning ACL port numbers based on ACL protocols
            if(!AclRule[0].equals("ip") && AclRule[6].equals("range")){
                port = AclRule[7].split("-");
            } else if(!AclRule[0].equals("ip") && AclRule[6].equals("eq")){
                port = new String[]{AclRule[7]};
            } else {
                port = new String[]{"any"};
            }

            for(int j=0; j<4; j++){
                if(srcIP[j].equals("0")){
                    inputSrcIP[j] = "0";
                }
                if(destIP[j].equals("0")){
                    inputDestIP[j] = "0";
                }
            }

            if(Arrays.toString(port).contains(inputPort) && Arrays.equals(srcIP, inputSrcIP) && Arrays.equals(destIP, inputDestIP)){
                display(permission, inputIP);
                break;
            } else if(Arrays.toString(port).contains("any") && Arrays.equals(srcIP, inputSrcIP) && Arrays.equals(destIP, inputDestIP)){
                display(permission, inputIP);
                break;
            }


            i++;
            // If ip address is not part of the ACL statements, then deny all
            if(i == ACLList.size()){
                display("deny", inputIP);
            }
        }
    }

    private static void display(String permission, String[] inputIP) {
        if(permission.equals("deny")){
            System.out.println("Packet from " + inputIP[0] + " to " + inputIP[1] + " on port " + inputIP[2] + " denied");
        } else if(permission.equals("permit")){
            System.out.println("Packet from " + inputIP[0] + " to " + inputIP[1] + " on port " + inputIP[2] + " permitted");
        }
    }
}

