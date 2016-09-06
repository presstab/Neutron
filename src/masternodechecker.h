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
        fSynced = false;
        mapAccepted.clear();
        mapPending.clear();
        mapRejected.clear();
    }

    void AddMasternode(CMasterNode* mn, bool fVerified = false);
    void ReconcileLists();
    void Reject(CMasterNode* mn, CNode* pnode);
    void SendVerifyRequest(CMasterNode* mn, CNode* pnode);
    void Accept(CMasterNode* mn, CNode* pnode);
    void RequestSyncWithPeers();
    void SendList(CNode* pnode);
    void ProcessCheckerMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);

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

    vector<CMasterNode> GetList()
    {
        vector<CMasterNode> vList;
        for(map<string, CMasterNode*>::iterator it = mapAccepted.begin(); it != mapAccepted.end(); it++)
            vList.push_back(*(*it).second);

        for(map<string, CMasterNode*>::iterator it = mapPending.begin(); it != mapPending.end(); it++)
            vList.push_back(*(*it).second);

        return vList;
    }

private:
    bool fSynced;
    map<string, CMasterNode*> mapAccepted;
    map<string, CMasterNode*> mapPending;
    map<string, CMasterNode*> mapRejected;
    map<string, CMasterNode*> mapTemp;

    void StatusAccepted(CMasterNode* mn)
    {
        mapAccepted[mn->vin.prevout.ToString()] = mn;

        if(mapPending.count(mn->vin.prevout.ToString()))
            mapPending.erase(mn->vin.prevout.ToString());
    }

    bool AlreadyHave(CMasterNode* mn)
    {
        if(mapPending.count(mn->vin.prevout.ToString()))
            return true;

        if(mapAccepted.count(mn->vin.prevout.ToString()))
            return true;

        if(mapRejected.count(mn->vin.prevout.ToString()))
            return true;

        return false;
    }
};
