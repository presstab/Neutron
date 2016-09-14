#ifndef MASTERNODECHECKER
#define MASTERNODECHECKER

#endif // MASTERNODECHECKER

#include "masternode.h"
#include "main.h"
#include "net.h"

using namespace std;

class CMasternodeChecker
{
public:
    CMasternodeChecker()
    {
        mapAccepted.clear();
        mapPending.clear();
        mapRejected.clear();
    }
    
    bool Dsee(CNode* pfrom, CMasterNode* mn);
    bool Dsee(CNode* pfrom, CTxIn vin, CService addr, CPubKey pubkey, CPubKey pubkey2, vector<unsigned char> vchSig, int64_t sigTime ,int64_t lastUpdated, int protocolVersion);
    void AddMasternode(CMasterNode* mn, bool fVerified = false);
    void SendVerifyRequest(CMasterNode* mn, CNode* pnode);
    void Accept(CMasterNode* mn, CNode* pnode);
    void Reject(CMasterNode* mn);
    void Reject(CMasterNode* mn, CNode* pnode);
    void RequestSyncWithPeers();
    void SendList(CNode* pnode);
    void ProcessCheckerMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    bool Synced()
    {
        return mapAccepted.size() > 1 && mapPending.empty();
    }

    vector<CMasterNode> GetAccepted()
    {
        vector<CMasterNode> vAccepted;
        for(map<string, CMasterNode>::iterator it = mapAccepted.begin(); it != mapAccepted.end(); it++)
            vAccepted.push_back((*it).second);

        return vAccepted;
    }

    int GetPendingCount()
    {
        return mapPending.size();
    }

    int GetMasternodeCount()
    {
        return mapAccepted.size() + mapPending.size();
    }

    bool InSync(int nCount);

    CMasterNode* GetNextPending();

private:
    bool fSynced;
    map<string, CMasterNode> mapAccepted;
    map<string, CMasterNode> mapPending;
    map<string, CMasterNode> mapRejected;
    map<string, CMasterNode> mapTemp;

    void StatusAccepted(CMasterNode* mn)
    {
        mapAccepted[mn->vin.prevout.ToString()] = *mn;

        if(mapPending.count(mn->vin.prevout.ToString()))
            mapPending.erase(mn->vin.prevout.ToString());
    }

    bool AlreadyHave(std::string strVin)
    {
        if(mapPending.count(strVin))
            return true;

        if(mapAccepted.count(strVin))
            return true;

        if(mapRejected.count(strVin))
            return true;

        return false;
    }

    bool AlreadyHave(CMasterNode* mn)
    {
        return AlreadyHave(mn->vin.prevout.ToString());
    }

    bool Get(std::string strVin, CMasterNode* mn)
    {
        if(mapPending.count(strVin))
            mn = &mapPending[strVin];
        else if(mapAccepted.count(strVin))
            mn = &mapAccepted[strVin];
        else if(mapRejected.count(strVin))
            mn = &mapRejected[strVin];
        else
            return false;

        return true;
    }
};
