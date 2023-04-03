package main.java.request;

/**
 * @author Denis Popolamov
 */

import main.java.other.Extensions;
import main.java.other.GeneralName;

import java.util.List;


/**
 *  Информационная часть запроса
 */
public class TBSRequest {

    private int version;
    private GeneralName requestorName;
    private List<Request> requestList;
    private Extensions requestExtensions;

    public TBSRequest(int version, GeneralName requestorName, List<Request> requestList,
                      Extensions requestExtensions) {
        this.version = version;
        this.requestorName = requestorName;
        this.requestList = requestList;
        this.requestExtensions = requestExtensions;
    }

    public int getVersion() {
        return version;
    }

    public GeneralName getRequestorName() {
        return requestorName;
    }

    public List<Request> getRequestList() {
        return requestList;
    }

    public Extensions getRequestExtensions() {
        return requestExtensions;
    }
}
