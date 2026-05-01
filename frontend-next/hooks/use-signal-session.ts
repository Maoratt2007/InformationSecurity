import { initiateX3DH } from '../lib/crypto/x3dh';

export function useSignalSession() {
  
  const establishSession = async (activeContactId: string, accessToken: string) => {
    // מניעת הפעלת הפונקציה אם אין משתמש פעיל (פותר את שגיאת ה-null)
    if (!activeContactId) return;

    // בדיקה אם כבר יש חיבור
    const existingSession = sessionStorage.getItem(`session_${activeContactId}`);
    if (existingSession) return;

    try {
      // משיכת המפתחות של הנמען מהשרת
      const response = await fetch(`http://127.0.0.1:8000/api/users/${activeContactId}/key-bundle`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      
      if (!response.ok) throw new Error("Failed to fetch key bundle");
      const receiverBundle = await response.json();

      // חיפוש המפתח ב-sessionStorage (יש למצוא את המפתח הנכון שלך)
      const storageKey = Object.keys(sessionStorage).find(key => key.includes('secure-messenger.signal.private-bundle'));
      
      if (!storageKey) {
        console.error("No private keys found in sessionStorage!");
        return;
      }

      const rawStorageData = sessionStorage.getItem(storageKey);
      if (!rawStorageData) return;

      const parsedData = JSON.parse(rawStorageData);
      // שימו לב: הנתונים יושבים תחת parsedData.privateBundle
      const myPrivateBundle = parsedData.privateBundle;

      // חישוב הסוד המשותף
      const { masterSecret, ephemeralPublicKey, usedOneTimePreKeyId } = await initiateX3DH(myPrivateBundle, receiverBundle);

      // שמירת הסשן
      sessionStorage.setItem(`session_${activeContactId}`, JSON.stringify({
        masterSecret,
        ephemeralPublicKey,
        usedOneTimePreKeyId
      }));

      console.log(`[Signal] Secure session established with ${activeContactId}`);

    } catch (error) {
      console.error("[Signal] Failed to establish secure session:", error);
    }
  };

  return { establishSession };
}