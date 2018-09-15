package ch.epfl.prifiproxy.persistence.entity;

import android.arch.persistence.room.Entity;
import android.arch.persistence.room.ForeignKey;
import android.arch.persistence.room.Ignore;
import android.arch.persistence.room.Index;
import android.arch.persistence.room.PrimaryKey;
import android.support.annotation.NonNull;

@Entity(foreignKeys = {@ForeignKey(entity = ConfigurationGroup.class, parentColumns = "id", childColumns = "groupId", onDelete = ForeignKey.CASCADE)},
        indices = {@Index("groupId")})
public class Configuration {
    @PrimaryKey(autoGenerate = true)
    private int id;

    @NonNull
    private String name = "";

    @NonNull
    private String host = "";

    private int relayPort;

    private int socksPort;

    private int priority;

    private boolean isActive;

    public Configuration() {
    }

    @Ignore
    public Configuration(int id, @NonNull String name, @NonNull String host, int relayPort, int socksPort, int priority, int groupId, boolean isActive) {
        this.id = id;
        this.name = name;
        this.host = host;
        this.relayPort = relayPort;
        this.socksPort = socksPort;
        this.priority = priority;
        this.groupId = groupId;
        this.isActive = isActive;
    }

    private int groupId;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @NonNull
    public String getName() {
        return name;
    }

    public void setName(@NonNull String name) {
        this.name = name;
    }

    @NonNull
    public String getHost() {
        return host;
    }

    public void setHost(@NonNull String host) {
        this.host = host;
    }

    public int getRelayPort() {
        return relayPort;
    }

    public void setRelayPort(int relayPort) {
        this.relayPort = relayPort;
    }

    public int getSocksPort() {
        return socksPort;
    }

    public void setSocksPort(int socksPort) {
        this.socksPort = socksPort;
    }

    public int getGroupId() {
        return groupId;
    }

    public void setGroupId(int groupId) {
        this.groupId = groupId;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }
}