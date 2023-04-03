package main.java.other;

/**
 * @author Denis Popolamov
 */

import java.util.Date;

public class Time {
    private UTCTime utcTime;
    private GeneralizedTime generalTime;

    public Time(UTCTime utcTime) {
        this.utcTime = utcTime;
    }

    public Time(GeneralizedTime generalTime) {
        this.generalTime = generalTime;
    }

    public UTCTime getUtcTime() {
        return utcTime;
    }

    public void setUtcTime(UTCTime utcTime) {
        this.utcTime = utcTime;
    }

    public GeneralizedTime getGeneralTime() {
        return generalTime;
    }

    public void setGeneralTime(GeneralizedTime generalTime) {
        this.generalTime = generalTime;
    }
}
