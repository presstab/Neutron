#ifndef MASTERNODECHECKER
#define MASTERNODECHECKER

#endif // MASTERNODECHECKER


#include "net.h"

using namespace std;
class CMasterNode;

class CMasternodeChecker
{
private:
    bool fSynced;
    vector<CMasterNode*> vAccepted;
    vector<CMasterNode*> vPending;
    vector<CMasterNode*> vRejected;

    void StatusAccepted(CMasterNode* mn)
    {
        vAccepted.push_back(mn);

        vector<CMasterNode*>::iterator it = find(vPending.begin(), vPending.end(), mn);
        assert(it != vPending.end());
        vPending.erase(it);
    }

public:
    CMasternodeChecker()
    {
        fSynced = false;
        vAccepted.clear();
        vPending.clear();
        vRejected.clear();
    }

    void AddMasternode(CMasterNode* mn);

    void Reject(CMasterNode* mn);

    void SendVerifyRequest(CMasterNode* mn, CNode* pnode);

    void Accept(CMasterNode* mn);

    int GetPendingCount()
    {
        return vPending.size();
    }

    CMasterNode* GetNextPending();
};
