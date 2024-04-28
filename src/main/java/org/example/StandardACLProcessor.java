package org.example;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class StandardACLProcessor {
    public static void main(String[] args) throws IOException {
        // Reads the Standard ACL files for ACL 1
        String ACLFile1 = "src/main/resources/Standard/ACLStatement1.txt";
        HashMap<Integer, String> ACLList1 = readACL(ACLFile1);
        // Reads the ip address list for standard ACL 1
        String ipFile1 = "src/main/resources/Standard/IPAddressList1.txt";
        List<String> IPList1 = readIpList(ipFile1);
        // Validates each ip address with the ACL statements for ACL 1
        System.out.println("Sample 1: Standard ACL Output 1".toUpperCase());
        for(String ip : IPList1){
            validateACL(ACLList1, ip);
        }
        System.out.println();

        // Reads the Standard ACL files for ACL 2
        String ACLFile2 = "src/main/resources/Standard/ACLStatement2.txt";
        HashMap<Integer, String> ACLList2 = readACL(ACLFile2);
        // Reads the ip address list for standard ACL 1
        String ipFile2 = "src/main/resources/Standard/IPAddressList2.txt";
        List<String> IPList2 = readIpList(ipFile2);
        // Validates each ip address with the ACL statements for ACL 2
        System.out.println("Sample 2: Standard ACL Output 2".toUpperCase());
        for(String ip : IPList2){
            validateACL(ACLList2, ip);
        }
        System.out.println();

        // Reads the Standard ACL files for ACL 3
        String ACLFile3 = "src/main/resources/Standard/ACLStatement3.txt";
        HashMap<Integer, String> ACLList3 = readACL(ACLFile3);
        // Reads the ip address list for standard ACL 1
        String ipFile3 = "src/main/resources/Standard/IPAddressList3.txt";
        List<String> IPList3 = readIpList(ipFile3);
        // Validates each ip address with the ACL statements for ACL 3
        System.out.println("Sample 3: Standard ACL Output 3".toUpperCase());
        for(String ip : IPList3){
            validateACL(ACLList3, ip);
        }
        System.out.println();

        // Reads the Standard ACL files for ACL 4
        String ACLFile4 = "src/main/resources/Standard/ACLStatement4.txt";
        HashMap<Integer, String> ACLList4 = readACL(ACLFile4);
        // Reads the ip address list for standard ACL 4
        String ipFile4 = "src/main/resources/Standard/IPAddressList4.txt";
        List<String> IPList4 = readIpList(ipFile4);
        // Validates each ip address with the ACL statements for ACL 3
        System.out.println("Sample 4: Standard ACL Output 4".toUpperCase());
        for(String ip : IPList4){
            validateACL(ACLList4, ip);
        }
    }

    // Private method to read the standard ACL file
    private static HashMap<Integer, String> readACL(String fileName) throws IOException {
        HashMap<Integer, String> ipList = new HashMap<>();

        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        int cnt = 0;
        while ((line = reader.readLine()) != null) {
            // Check if line starts with "access-list"
            if (line.startsWith("access-list")) {
                //Store ip address into key value pair
                String[] acl = line.split(" ");
                String[] ip = {"0","0","0","0"};
                String[] mask = {"255","255","255","255"};

                if(!acl[3].equals("any")){
                    ip = acl[3].split("\\.");
                    mask = acl[4].split("\\.");
                }

                // Updates the ip address based on the masks
                for(int i=0; i<4; i++){
                    if(mask[i].equals("255")){
                        ip[i] = "0";
                    }
                }

                // Formats the updated address into a string
                acl[3] = Arrays.toString(ip).replaceAll("[\\[\\]\"]","").replaceAll(", ",".");
                // Adds the ACL details to the Hashmap in the format permission_ipAddr
                // If the first ACL statement is "access-list 3 deny 172.16.4.0 0.0.0.255" then the hashmap value would be 0=deny_172.16.4.0
                // If the second ACL statement is "access-list 3 permit 172.16.0.0 0.0.255.255" the hashmap value is 1=permit_172.16.0.0
                ipList.put(cnt, acl[2]+"_"+acl[3]);
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
            IPList.add(line);
        }
        reader.close();
        return IPList;
    }

    // Method to validate the IP address based on the given ACL
    private static void validateACL(HashMap<Integer, String> ACLList, String ip){
        String[] AclRule, srcIP;
        String permission;
        boolean res;
        int i = 0;

        while(i<ACLList.size()){
            String[] inputIP = ip.split("\\.");
            AclRule = ACLList.get(i).split("_");
            permission = AclRule[0];
            srcIP = AclRule[1].split("\\.");

            for(int j=0; j<4; j++){
                if(srcIP[j].equals("0")){
                    inputIP[j] = "0";
                }
            }

            // If ip address is part of the ACL statements
            if(Arrays.equals(srcIP, inputIP)){
                if(permission.equals("deny")){
                    System.out.println("Packet from " + ip + " denied");
                } else if(permission.equals("permit")){
                    System.out.println("Packet from " + ip + " permitted");
                }
                break;
            }
            i++;

            // If ip address is not part of the ACL statements, then deny all
            if(i == ACLList.size()){
                System.out.println("Packet from " + ip + " denied");
            }
        }
    }

}