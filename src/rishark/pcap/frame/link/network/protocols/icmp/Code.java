package rishark.pcap.frame.link.network.protocols.icmp;

import java.util.Arrays;

public enum Code {

    No_Code_(Type.Echo_Reply, 0),
    Net_Unreachable(Type.Destination_Unreachable, 0),
    Host_Unreachable(Type.Destination_Unreachable, 1),
    Protocol_Unreachable(Type.Destination_Unreachable,2),
    Port_Unreachable(Type.Destination_Unreachable,3),
    Fragmentation_Needed_and_Dont_Fragment_was_Set(Type.Destination_Unreachable,4),
    Source_Route_Failed(Type.Destination_Unreachable,5),
    Destination_Network_Unknown(Type.Destination_Unreachable,6),
    Destination_Host_Unknown(Type.Destination_Unreachable,7),
    Source_Host_Isolated(Type.Destination_Unreachable,8),
    Communication_with_Destination_Network_is_Administratively_Prohibited(Type.Destination_Unreachable,9),
    Communication_with_Destination_Host_is_Administratively_Prohibited(Type.Destination_Unreachable,10),
    Destination_Network_Unreachable_for_Type_of_Service(Type.Destination_Unreachable,11),
    Destination_Host_Unreachable_for_Type_pf_Service(Type.Destination_Unreachable,12),
    Communication_Administratively_Prohibited(Type.Destination_Unreachable,13),
    Host_Precedence_Violation(Type.Destination_Unreachable,14),
    Precedence_cutoff_in_effect(Type.Destination_Unreachable,15),
    No_Code__(Type.Source_Quench, 0),
    Redirect_Datagram_for_the_Network(Type.Redirect, 0),
    Redirect_Datagram_for_the_Host(Type.Redirect,1),
    Redirect_Datagram_for_the_Type_of_Service_and_Network(Type.Redirect,2),
    Redirect_Datagram_for_the_Type_of_Service_and_Host(Type.Redirect,3),
    Alternate_Address_for_Host(Type.Alternate_Host_Address, 0),
    No_Code(Type.Echo, 0),
    Normal_router_advertisement(Type.Router_Advertisement, 0),
    Does_not_route_common_traffic(Type.Router_Advertisement, 16),
    No_Code___(Type.Router_Selection, 0),
    Time_to_Live_exceed_in_Transit(Type.Time_Exceeded, 0),
    Fragment_Reassembly_Time_Exceed(Type.Time_Exceeded, 1),
    Pointer_indicates_the_error(Type.Parameter_Problem, 0),
    Missing_a_Required_Option(Type.Parameter_Problem, 1),
    Bad_Length(Type.Parameter_Problem, 2),
    No___Code__(Type.Timestamp, 0),
    No__Code(Type.Timestamp_Reply, 0),
    No___Code(Type.Information_Request, 0),
    No__Code_(Type.Information_Reply, 0),
    No__Code__(Type.Address_Mask_Reply, 0),
    No__Code___(Type.Address_Mask_Request, 0),
    Bad_SPI(Type.Photuris, 0),
    Authentification_Failed(Type.Photuris, 1),
    Decompression_Failed(Type.Photuris, 2),
    Decryption_Failed(Type.Photuris, 3),
    Need_Authentication(Type.Photuris, 4),
    Need_Authorization(Type.Photuris, 5),
    No_Error(Type.Extended_Echo_Request, 0),
    No_Error_(Type.Extended_Echo_Reply, 0),
    Malformed_Query(Type.Extended_Echo_Reply, 1),
    No_Such_Interface(Type.Extended_Echo_Reply, 2),
    No_Such_Table_Entry(Type.Extended_Echo_Reply, 3),
    Multiple_Intefaces_Satisfy_Query(Type.Extended_Echo_Reply, 4);

    private final int code;
    private final Type type;

    Code(Type type, int code) {
        this.code = code;
        this.type = type;
    }

    public static Code findCode(Type t, int i){
        for(Code c : Code.values()) {
            if (c.getType().equals(t))
                if(c.getCode() == i)
                    return c;
        }
        return null;
    }

    public int getCode() {
        return code;
    }

    public Type getType() {
        return type;
    }
}
