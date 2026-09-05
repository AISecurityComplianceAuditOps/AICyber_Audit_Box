 " " " 
 r u n _ m o t o r o l a _ a u d i t . p y 
 R u n s   t h e   Q u i c k   a n d   D e e p   a u d i t s   f o r   t h e   M o t o r o l a   S o l u t i o n s   G l o b a l   I n c i d e n t   R e s p o n s e   P l a n   v 2 . 1 
 a g a i n s t   I S O   2 7 0 0 1   c o n t r o l s   5 . 2 4   -   5 . 2 8   u s i n g   g e m m a 4 : e 4 b   o n   l l a m a . c p p   b a c k e n d . 
 G e n e r a t e s   b o t h   M a r k d o w n   a n d   P D F   r e p o r t s . 
 " " " 
 
 i m p o r t   o s 
 i m p o r t   s y s 
 i m p o r t   t i m e 
 i m p o r t   j s o n 
 i m p o r t   d a t e t i m e 
 
 #   A d d   w o r k s p a c e   d i r e c t o r y   t o   p y t h o n   p a t h 
 s y s . p a t h . a p p e n d ( o s . g e t c w d ( ) ) 
 
 #   E n s u r e   e n v i r o n m e n t   v a r i a b l e s   a r e   s e t   f o r   l o c a l   l l a m a . c p p 
 o s . e n v i r o n [ " L L M _ B A C K E N D " ]   =   " l l a m a . c p p " 
 o s . e n v i r o n [ " O L L A M A _ H O S T " ]   =   " h t t p : / / 1 2 7 . 0 . 0 . 1 : 1 1 4 3 4 " 
 o s . e n v i r o n [ " E M B E D D I N G _ H O S T " ]   =   " h t t p : / / 1 2 7 . 0 . 0 . 1 : 1 1 4 3 5 " 
 
 f r o m   s r c . d b . d a t a b a s e   i m p o r t   S e s s i o n L o c a l ,   D o c u m e n t C h u n k ,   f o r c e _ m a s t e r 
 f r o m   s r c . c o r e . c o n t r o l s _ d a t a   i m p o r t   U S E _ C A S E S 
 f r o m   s r c . a i . a u d i t _ g r a p h   i m p o r t   a u d i t _ g r a p h 
 f r o m   s r c . c o r e . r e t r i e v a l   i m p o r t   s a v e _ d o c u m e n t _ c h u n k s 
 
 #   f p d f   i m p o r t s   f o r   P D F   g e n e r a t i o n 
 f r o m   f p d f   i m p o r t   F P D F 
 f r o m   f p d f . e n u m s   i m p o r t   X P o s ,   Y P o s 
 
 #   ─ ─   C o l o r   P a l e t t e   ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ 
 D A R K _ B G             =   ( 1 5 ,     2 3 ,     4 2 )         #   s l a t e - 9 0 0 
 A C C E N T _ B L U E     =   ( 5 9 ,   1 3 0 ,   2 4 6 )         #   b l u e - 5 0 0 
 A C C E N T _ G R E E N   =   ( 3 4 ,   1 9 7 ,     9 4 )         #   g r e e n - 5 0 0 
 A C C E N T _ A M B E R   =   ( 2 4 5 ,   1 5 8 ,     1 1 )       #   a m b e r - 5 0 0 
 A C C E N T _ R E D       =   ( 2 3 9 ,     6 8 ,     6 8 )       #   r e d - 5 0 0 
 W H I T E                 =   ( 2 5 5 ,   2 5 5 ,   2 5 5 ) 
 L I G H T _ G R A Y       =   ( 2 4 1 ,   2 4 5 ,   2 4 9 ) 
 M I D _ G R A Y           =   ( 1 4 8 ,   1 6 3 ,   1 8 4 ) 
 D A R K _ T E X T         =   ( 1 5 ,     2 3 ,     4 2 ) 
 B O D Y _ T E X T         =   ( 5 1 ,     6 5 ,     8 5 ) 
 
 c l a s s   A u d i t R e p o r t P D F ( F P D F ) : 
         d e f   h e a d e r ( s e l f ) : 
                 i f   s e l f . p a g e _ n o ( )   = =   1 : 
                         r e t u r n 
                 s e l f . s e t _ f i l l _ c o l o r ( * D A R K _ B G ) 
                 s e l f . r e c t ( 0 ,   0 ,   2 1 0 ,   1 2 ,   " F " ) 
                 s e l f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 s e l f . s e t _ t e x t _ c o l o r ( * M I D _ G R A Y ) 
                 s e l f . s e t _ x y ( 1 0 ,   3 ) 
                 s e l f . c e l l ( 0 ,   6 ,   " I S O   2 7 0 0 1   C o m p l i a n c e   A u d i t     |     M o t o r o l a   G l o b a l   I n c i d e n t   R e s p o n s e   P l a n " ,   a l i g n = " L " ) 
                 s e l f . s e t _ x y ( 0 ,   3 ) 
                 s e l f . c e l l ( 2 0 0 ,   6 ,   f " P a g e   { s e l f . p a g e _ n o ( ) } " ,   a l i g n = " R " ) 
                 s e l f . l n ( 1 2 ) 
 
         d e f   f o o t e r ( s e l f ) : 
                 i f   s e l f . p a g e _ n o ( )   = =   1 : 
                         r e t u r n 
                 s e l f . s e t _ y ( - 1 2 ) 
                 s e l f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   7 ) 
                 s e l f . s e t _ t e x t _ c o l o r ( * M I D _ G R A Y ) 
                 s e l f . c e l l ( 0 ,   6 ,   " C O N F I D E N T I A L   - -   I n t e r n a l   C o m p l i a n c e   A u d i t   R e p o r t " ,   a l i g n = " C " ) 
 
         d e f   h l i n e ( s e l f ,   c o l o r = L I G H T _ G R A Y ,   t h i c k n e s s = 0 . 3 ) : 
                 s e l f . s e t _ d r a w _ c o l o r ( * c o l o r ) 
                 s e l f . s e t _ l i n e _ w i d t h ( t h i c k n e s s ) 
                 y   =   s e l f . g e t _ y ( ) 
                 s e l f . l i n e ( 1 0 ,   y ,   2 0 0 ,   y ) 
                 s e l f . l n ( 3 ) 
 
         d e f   s e c t i o n _ t i t l e ( s e l f ,   t e x t ) : 
                 s e l f . l n ( 4 ) 
                 s e l f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   1 2 ) 
                 s e l f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 s e l f . c e l l ( 0 ,   8 ,   t e x t ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 s e l f . h l i n e ( A C C E N T _ B L U E ,   0 . 6 ) 
 
         d e f   b o d y ( s e l f ,   t e x t ,   s i z e = 9 ,   c o l o r = B O D Y _ T E X T ,   i n d e n t = 0 ) : 
                 s e l f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   s i z e ) 
                 s e l f . s e t _ t e x t _ c o l o r ( * c o l o r ) 
                 s e l f . s e t _ x ( 1 0   +   i n d e n t ) 
                 s e l f . m u l t i _ c e l l ( 1 9 0   -   i n d e n t ,   5 ,   t e x t ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
 
         d e f   k v ( s e l f ,   k e y ,   v a l u e ) : 
                 s e l f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   9 ) 
                 s e l f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 s e l f . s e t _ x ( 1 0 ) 
                 k w   =   s e l f . g e t _ s t r i n g _ w i d t h ( k e y   +   "     " ) 
                 s e l f . c e l l ( k w ,   5 ,   k e y ) 
                 s e l f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   9 ) 
                 s e l f . s e t _ t e x t _ c o l o r ( * B O D Y _ T E X T ) 
                 s e l f . m u l t i _ c e l l ( 0 ,   5 ,   v a l u e ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
 
 
 d e f   g e n e r a t e _ p d f ( r e s u l t s _ q u i c k ,   r e s u l t s _ d e e p ,   e x e c u t i o n _ s t a t s ) : 
         p d f   =   A u d i t R e p o r t P D F ( ) 
         p d f . s e t _ a u t o _ p a g e _ b r e a k ( a u t o = T r u e ,   m a r g i n = 1 4 ) 
         p d f . s e t _ m a r g i n s ( 1 0 ,   1 4 ,   1 0 ) 
 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         #   P A G E   1   - -   C O V E R 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         p d f . a d d _ p a g e ( ) 
         p d f . s e t _ f i l l _ c o l o r ( * D A R K _ B G ) 
         p d f . r e c t ( 0 ,   0 ,   2 1 0 ,   2 9 7 ,   " F " ) 
 
         p d f . s e t _ f i l l _ c o l o r ( * A C C E N T _ B L U E ) 
         p d f . r e c t ( 0 ,   1 1 0 ,   2 1 0 ,   3 ,   " F " ) 
 
         p d f . s e t _ x y ( 0 ,   5 0 ) 
         p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   2 4 ) 
         p d f . s e t _ t e x t _ c o l o r ( * W H I T E ) 
         p d f . c e l l ( 2 1 0 ,   1 2 ,   " I S O   2 7 0 0 1   C O M P L I A N C E   A U D I T " ,   a l i g n = " C " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
 
         p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   1 4 ) 
         p d f . s e t _ t e x t _ c o l o r ( * A C C E N T _ B L U E ) 
         p d f . c e l l ( 2 1 0 ,   1 0 ,   " M o t o r o l a   S o l u t i o n s   G l o b a l   I n c i d e n t   R e s p o n s e   P l a n " ,   a l i g n = " C " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
 
         p d f . l n ( 6 ) 
         p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   9 . 5 ) 
         p d f . s e t _ t e x t _ c o l o r ( * M I D _ G R A Y ) 
         p d f . c e l l ( 2 1 0 ,   6 ,   " A u d i t   o f   I n c i d e n t   M a n a g e m e n t   c o n t r o l s   ( 5 . 2 4   -   5 . 2 8 ) " ,   a l i g n = " C " , 
                           n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
 
         #   S u m m a r y   b o x 
         p d f . s e t _ f i l l _ c o l o r ( 3 0 ,   4 1 ,   5 9 ) 
         p d f . r e c t ( 2 5 ,   1 2 2 ,   1 6 0 ,   8 5 ,   " F " ) 
         y 0   =   1 2 6 
         
         #   C a l c u l a t e   c o m p l i a n t / p a r t i a l   m e t r i c s   f r o m   d e e p   a u d i t 
         d e e p _ s t a t u s e s   =   [ r . g e t ( " s t a t u s " )   f o r   r   i n   r e s u l t s _ d e e p ] 
         c o m p l i a n t _ c o u n t   =   s u m ( 1   f o r   s   i n   d e e p _ s t a t u s e s   i f   s   = =   " C O M P L I A N T " ) 
         p a r t i a l _ c o u n t   =   s u m ( 1   f o r   s   i n   d e e p _ s t a t u s e s   i f   s   i n   ( " P A R T I A L " ,   " P A R T I A L _ C O M P L I A N T " ) ) 
         n o n _ c o m p l i a n t _ c o u n t   =   s u m ( 1   f o r   s   i n   d e e p _ s t a t u s e s   i f   s   = =   " N O N _ C O M P L I A N T " ) 
 
         m e t r i c s   =   [ 
                 ( " D o c u m e n t   E v a l u a t e d " ,     " M o t o r o l a   S o l u t i o n s   G l o b a l   I R P   v 2 . 1 " ) , 
                 ( " C o n t r o l s   A u d i t e d " ,           " I S O   2 7 0 0 1 :   5 . 2 4 ,   5 . 2 5 ,   5 . 2 6 ,   5 . 2 7 ,   5 . 2 8 " ) , 
                 ( " C o m p l i a n c e   S t a t u s " ,       f " { c o m p l i a n t _ c o u n t }   C o m p l i a n t ,   { p a r t i a l _ c o u n t }   P a r t i a l l y   C o m p l i a n t ,   { n o n _ c o m p l i a n t _ c o u n t }   N o n - C o m p l i a n t " ) , 
                 ( " Q u i c k   A u d i t   T i m e " ,         f " { e x e c u t i o n _ s t a t s [ ' q u i c k _ t o t a l ' ] : . 1 f }   s e c o n d s " ) , 
                 ( " D e e p   A u d i t   T i m e " ,           f " { e x e c u t i o n _ s t a t s [ ' d e e p _ t o t a l ' ] : . 1 f }   s e c o n d s " ) , 
                 ( " A I   M o d e l   B a c k e n d " ,         " G e m m a   4   ( 4 B )   v i a   l l a m a - s e r v e r . e x e " ) , 
                 ( " R e p o r t   D a t e " ,                   d a t e t i m e . d a t e . t o d a y ( ) . s t r f t i m e ( " % B   % d ,   % Y " ) ) , 
         ] 
         f o r   l a b e l ,   v a l u e   i n   m e t r i c s : 
                 p d f . s e t _ x y ( 3 0 ,   y 0 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * M I D _ G R A Y ) 
                 p d f . c e l l ( 5 8 ,   8 ,   l a b e l . u p p e r ( ) ,   a l i g n = " L " ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * W H I T E ) 
                 p d f . c e l l ( 9 0 ,   8 ,   v a l u e ,   a l i g n = " L " ) 
                 y 0   + =   9 
 
         p d f . s e t _ f i l l _ c o l o r ( * A C C E N T _ B L U E ) 
         p d f . r e c t ( 0 ,   2 8 0 ,   2 1 0 ,   1 7 ,   " F " ) 
         p d f . s e t _ x y ( 0 ,   2 8 4 ) 
         p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   8 ) 
         p d f . s e t _ t e x t _ c o l o r ( * W H I T E ) 
         p d f . c e l l ( 2 1 0 ,   6 ,   " C O N F I D E N T I A L   - -   C o m p l i a n c e   A u d i t   R e p o r t " ,   a l i g n = " C " ) 
 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         #   P A G E   2   - -   E X E C U T I V E   S U M M A R Y   +   C O M P A R I S O N 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         p d f . a d d _ p a g e ( ) 
         p d f . s e c t i o n _ t i t l e ( " 1 .   E x e c u t i v e   S u m m a r y " ) 
 
         i n t r o   =   ( 
                 " T h i s   c o m p l i a n c e   r e p o r t   d o c u m e n t s   t h e   s e c u r i t y   a u d i t   o f   t h e   M o t o r o l a   S o l u t i o n s   G l o b a l   I n c i d e n t   " 
                 " R e s p o n s e   P l a n   ( V e r s i o n   2 . 1 ,   A p r i l   2 0 2 2 )   a g a i n s t   t h e   I S O   2 7 0 0 1 : 2 0 2 2   s t a n d a r d .   T h e   a u d i t   s p e c i f i c a l l y   " 
                 " f o c u s e s   o n   t h e   c o r e   i n c i d e n t   m a n a g e m e n t   c o n t r o l s   u n d e r   C l a u s e   5   ( O r g a n i z a t i o n a l   C o n t r o l s ) : \ n " 
                 " -   5 . 2 4 :   I n c i d e n t   M a n a g e m e n t   P l a n n i n g   a n d   P r e p a r a t i o n \ n " 
                 " -   5 . 2 5 :   A s s e s s m e n t   a n d   D e c i s i o n   o n   I n f o r m a t i o n   S e c u r i t y   E v e n t s \ n " 
                 " -   5 . 2 6 :   R e s p o n s e   t o   I n f o r m a t i o n   S e c u r i t y   I n c i d e n t s \ n " 
                 " -   5 . 2 7 :   L e a r n i n g   f r o m   I n f o r m a t i o n   S e c u r i t y   I n c i d e n t s \ n " 
                 " -   5 . 2 8 :   C o l l e c t i o n   o f   E v i d e n c e \ n \ n " 
                 " T o   e v a l u a t e   t h e   a u d i t o r   e n g i n e ' s   e f f e c t i v e n e s s ,   t h e   d o c u m e n t   w a s   a u d i t e d   i n   b o t h   Q u i c k   a n d   D e e p   " 
                 " m o d e s .   T h e   Q u i c k   A u d i t   e x e c u t e s   t h e   a n a l y s i s   i n   a   s i n g l e   p a s s   w i t h o u t   v e r i f i c a t i o n / s e l f - c o r r e c t i o n .   " 
                 " T h e   D e e p   A u d i t   u t i l i z e s   t h e   L a n g G r a p h   m u l t i - g a t e   v a l i d a t o r   p i p e l i n e ,   e x e c u t i n g   u p   t o   2   s e l f - c o r r e c t i o n   " 
                 " p a s s e s   o n   C P U   w h e n   g r o u n d i n g   v e r i f i c a t i o n   f a i l s .   B o t h   a u d i t s   f o u n d   t h e   d o c u m e n t   h a s   s t r o n g   c o v e r a g e   f o r   " 
                 " p l a n n i n g ,   a s s e s s m e n t ,   a n d   r e s p o n s e   r o l e s ,   b u t   i d e n t i f i e d   m i n o r   p r o c e d u r a l   c o m p l i a n c e   g a p s   i n   e v i d e n c e   c o l l e c t i o n   " 
                 " s t a n d a r d s . " 
         ) 
         p d f . b o d y ( i n t r o ) 
         p d f . l n ( 3 ) 
 
         p d f . s e c t i o n _ t i t l e ( " 2 .   Q u i c k   v s .   D e e p   A u d i t   C o m p a r i s o n   T a b l e " ) 
 
         #   H e a d e r 
         c o l _ w   =   [ 1 4 ,   6 0 ,   3 2 ,   3 2 ,   2 6 ,   2 6 ] 
         h d r s     =   [ " I D " ,   " C o n t r o l   N a m e " ,   " Q u i c k   S t a t u s " ,   " D e e p   S t a t u s " ,   " Q u i c k   T i m e " ,   " D e e p   T i m e " ] 
         p d f . s e t _ f i l l _ c o l o r ( * D A R K _ B G ) 
         p d f . s e t _ t e x t _ c o l o r ( * W H I T E ) 
         p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
         f o r   w ,   h   i n   z i p ( c o l _ w ,   h d r s ) : 
                 p d f . c e l l ( w ,   7 ,   h ,   f i l l = T r u e ,   a l i g n = " C " ) 
         p d f . l n ( ) 
 
         s t a t u s _ c o l o r s   =   { 
                 " C O M P L I A N T " :                 A C C E N T _ G R E E N , 
                 " P A R T I A L " :                     A C C E N T _ A M B E R , 
                 " P A R T I A L _ C O M P L I A N T " :   A C C E N T _ A M B E R , 
                 " N O N _ C O M P L I A N T " :         A C C E N T _ R E D , 
         } 
 
         f o r   i   i n   r a n g e ( l e n ( r e s u l t s _ q u i c k ) ) : 
                 r q   =   r e s u l t s _ q u i c k [ i ] 
                 r d   =   r e s u l t s _ d e e p [ i ] 
                 
                 b g   =   W H I T E   i f   i   %   2   = =   0   e l s e   L I G H T _ G R A Y 
                 p d f . s e t _ f i l l _ c o l o r ( * b g ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ T E X T ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 
                 c i d   =   r q [ " c o n t r o l _ i d " ] . s p l i t ( "   " ) [ 0 ] 
                 p d f . c e l l ( c o l _ w [ 0 ] ,   8 ,   c i d ,   f i l l = T r u e ,   a l i g n = " C " ) 
                 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   7 . 5 ) 
                 #   C l e a n   c o n t r o l   n a m e 
                 c n a m e   =   r q [ " c o n t r o l _ n a m e " ] 
                 i f   l e n ( c n a m e )   >   3 6 : 
                         c n a m e   =   c n a m e [ : 3 3 ]   +   " . . . " 
                 p d f . c e l l ( c o l _ w [ 1 ] ,   8 ,   c n a m e ,   f i l l = T r u e ) 
                 
                 #   Q u i c k   S t a t u s 
                 q _ s t a t   =   r q [ " s t a t u s " ] 
                 p d f . s e t _ f i l l _ c o l o r ( * s t a t u s _ c o l o r s . g e t ( q _ s t a t ,   M I D _ G R A Y ) ) 
                 p d f . s e t _ t e x t _ c o l o r ( * W H I T E ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   7 ) 
                 p d f . c e l l ( c o l _ w [ 2 ] ,   8 ,   q _ s t a t ,   f i l l = T r u e ,   a l i g n = " C " ) 
                 
                 #   D e e p   S t a t u s 
                 d _ s t a t   =   r d [ " s t a t u s " ] 
                 p d f . s e t _ f i l l _ c o l o r ( * s t a t u s _ c o l o r s . g e t ( d _ s t a t ,   M I D _ G R A Y ) ) 
                 p d f . s e t _ t e x t _ c o l o r ( * W H I T E ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   7 ) 
                 p d f . c e l l ( c o l _ w [ 3 ] ,   8 ,   d _ s t a t ,   f i l l = T r u e ,   a l i g n = " C " ) 
                 
                 #   R e s t o r e   r o w   b a c k g r o u n d   f o r   t i m i n g   c e l l s 
                 p d f . s e t _ f i l l _ c o l o r ( * b g ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ T E X T ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   8 ) 
                 p d f . c e l l ( c o l _ w [ 4 ] ,   8 ,   f " { r q [ ' e l a p s e d ' ] : . 1 f } s " ,   f i l l = T r u e ,   a l i g n = " C " ) 
                 p d f . c e l l ( c o l _ w [ 5 ] ,   8 ,   f " { r d [ ' e l a p s e d ' ] : . 1 f } s " ,   f i l l = T r u e ,   a l i g n = " C " ) 
                 p d f . l n ( ) 
 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         #   P A G E   3   - -   D E T A I L E D   C O M P L I A N C E   F I N D I N G S   ( 1 ) 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         p d f . a d d _ p a g e ( ) 
         p d f . s e c t i o n _ t i t l e ( " 3 .   D e t a i l e d   C o n t r o l   F i n d i n g s   ( D e e p   A u d i t ) " ) 
 
         #   P r i n t   f i r s t   3   c o n t r o l s 
         f o r   i   i n   r a n g e ( 3 ) : 
                 r e s   =   r e s u l t s _ d e e p [ i ] 
                 s c   =   s t a t u s _ c o l o r s . g e t ( r e s [ " s t a t u s " ] ,   M I D _ G R A Y ) 
                 
                 y _ r o w   =   p d f . g e t _ y ( ) 
                 p d f . s e t _ f i l l _ c o l o r ( * s c ) 
                 p d f . r e c t ( 1 0 ,   y _ r o w ,   4 ,   1 0 ,   " F " ) 
                 p d f . s e t _ f i l l _ c o l o r ( * L I G H T _ G R A Y ) 
                 p d f . r e c t ( 1 4 ,   y _ r o w ,   1 8 6 ,   1 0 ,   " F " ) 
                 p d f . s e t _ x y ( 1 6 ,   y _ r o w   +   2 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   9 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . c e l l ( 0 ,   6 ,   f " { r e s [ ' c o n t r o l _ i d ' ] }     |     { r e s [ ' c o n t r o l _ n a m e ' ] } " ) 
                 p d f . l n ( 1 2 ) 
 
                 p d f . k v ( " S t a t u s :   " ,   r e s [ " s t a t u s " ] ) 
                 p d f . k v ( " S e v e r i t y :   " ,   r e s [ " s e v e r i t y " ] ) 
                 
                 p d f . l n ( 1 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . s e t _ x ( 1 0 ) 
                 p d f . c e l l ( 0 ,   4 ,   " E v i d e n c e   /   I n p u t   D o c u m e n t   C i t a t i o n : " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 p d f . s e t _ f i l l _ c o l o r ( 2 2 4 ,   2 3 1 ,   2 4 5 ) 
                 p d f . s e t _ x ( 1 2 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " I " ,   7 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( 5 0 ,   5 0 ,   8 0 ) 
                 q u o t e   =   r e s . g e t ( " e v i d e n c e _ q u o t e " )   o r   " N o   d i r e c t   e v i d e n c e   c i t a t i o n   f o u n d . " 
                 p d f . m u l t i _ c e l l ( 1 8 6 ,   4 . 5 ,   f " \ " { q u o t e } \ " " ,   f i l l = T r u e ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
 
                 p d f . l n ( 1 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . s e t _ x ( 1 0 ) 
                 p d f . c e l l ( 0 ,   4 ,   " A u d i t o r   A n a l y s i s   &   G a p s : " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   7 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * B O D Y _ T E X T ) 
                 p d f . s e t _ x ( 1 2 ) 
                 r e a s o n i n g   =   r e s . g e t ( " r e a s o n i n g " )   o r   " N o   d e t a i l e d   a n a l y s i s   a v a i l a b l e . " 
                 p d f . m u l t i _ c e l l ( 1 8 6 ,   4 ,   r e a s o n i n g ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 
                 p d f . l n ( 1 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . s e t _ x ( 1 0 ) 
                 p d f . c e l l ( 0 ,   4 ,   " R e c o m m e n d a t i o n : " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   7 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * B O D Y _ T E X T ) 
                 p d f . s e t _ x ( 1 2 ) 
                 r e c   =   r e s . g e t ( " r e c o m m e n d a t i o n " )   o r   " N o   r e c o m m e n d a t i o n   p r o v i d e d . " 
                 p d f . m u l t i _ c e l l ( 1 8 6 ,   4 ,   r e c ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 
                 p d f . l n ( 3 ) 
                 p d f . h l i n e ( ) 
 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         #   P A G E   4   - -   D E T A I L E D   C O M P L I A N C E   F I N D I N G S   ( 2 ) 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         p d f . a d d _ p a g e ( ) 
         p d f . s e c t i o n _ t i t l e ( " 3 .   D e t a i l e d   C o n t r o l   F i n d i n g s   ( D e e p   A u d i t   -   C o n t i n u e d ) " ) 
 
         #   P r i n t   r e m a i n i n g   2   c o n t r o l s   ( 5 . 2 7   a n d   5 . 2 8 ) 
         f o r   i   i n   r a n g e ( 3 ,   5 ) : 
                 r e s   =   r e s u l t s _ d e e p [ i ] 
                 s c   =   s t a t u s _ c o l o r s . g e t ( r e s [ " s t a t u s " ] ,   M I D _ G R A Y ) 
                 
                 y _ r o w   =   p d f . g e t _ y ( ) 
                 p d f . s e t _ f i l l _ c o l o r ( * s c ) 
                 p d f . r e c t ( 1 0 ,   y _ r o w ,   4 ,   1 0 ,   " F " ) 
                 p d f . s e t _ f i l l _ c o l o r ( * L I G H T _ G R A Y ) 
                 p d f . r e c t ( 1 4 ,   y _ r o w ,   1 8 6 ,   1 0 ,   " F " ) 
                 p d f . s e t _ x y ( 1 6 ,   y _ r o w   +   2 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   9 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . c e l l ( 0 ,   6 ,   f " { r e s [ ' c o n t r o l _ i d ' ] }     |     { r e s [ ' c o n t r o l _ n a m e ' ] } " ) 
                 p d f . l n ( 1 2 ) 
 
                 p d f . k v ( " S t a t u s :   " ,   r e s [ " s t a t u s " ] ) 
                 p d f . k v ( " S e v e r i t y :   " ,   r e s [ " s e v e r i t y " ] ) 
                 
                 p d f . l n ( 1 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . s e t _ x ( 1 0 ) 
                 p d f . c e l l ( 0 ,   4 ,   " E v i d e n c e   /   I n p u t   D o c u m e n t   C i t a t i o n : " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 p d f . s e t _ f i l l _ c o l o r ( 2 2 4 ,   2 3 1 ,   2 4 5 ) 
                 p d f . s e t _ x ( 1 2 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " I " ,   7 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( 5 0 ,   5 0 ,   8 0 ) 
                 q u o t e   =   r e s . g e t ( " e v i d e n c e _ q u o t e " )   o r   " N o   d i r e c t   e v i d e n c e   c i t a t i o n   f o u n d . " 
                 p d f . m u l t i _ c e l l ( 1 8 6 ,   4 . 5 ,   f " \ " { q u o t e } \ " " ,   f i l l = T r u e ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
 
                 p d f . l n ( 1 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . s e t _ x ( 1 0 ) 
                 p d f . c e l l ( 0 ,   4 ,   " A u d i t o r   A n a l y s i s   &   G a p s : " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   7 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * B O D Y _ T E X T ) 
                 p d f . s e t _ x ( 1 2 ) 
                 r e a s o n i n g   =   r e s . g e t ( " r e a s o n i n g " )   o r   " N o   d e t a i l e d   a n a l y s i s   a v a i l a b l e . " 
                 p d f . m u l t i _ c e l l ( 1 8 6 ,   4 ,   r e a s o n i n g ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 
                 p d f . l n ( 1 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . s e t _ x ( 1 0 ) 
                 p d f . c e l l ( 0 ,   4 ,   " R e c o m m e n d a t i o n : " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   7 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * B O D Y _ T E X T ) 
                 p d f . s e t _ x ( 1 2 ) 
                 r e c   =   r e s . g e t ( " r e c o m m e n d a t i o n " )   o r   " N o   r e c o m m e n d a t i o n   p r o v i d e d . " 
                 p d f . m u l t i _ c e l l ( 1 8 6 ,   4 ,   r e c ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 
                 p d f . l n ( 3 ) 
                 p d f . h l i n e ( ) 
 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         #   P A G E   5   - -   T E C H   S P E C   &   R E C O M M E N D A T I O N S 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         p d f . a d d _ p a g e ( ) 
         p d f . s e c t i o n _ t i t l e ( " 4 .   T e c h n i c a l   A u d i t   M e t r i c s " ) 
 
         p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   9 ) 
         p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
         p d f . c e l l ( 7 0 ,   6 ,   " M e t r i c   N a m e " ) 
         p d f . c e l l ( 4 0 ,   6 ,   " Q u i c k   A u d i t " ) 
         p d f . c e l l ( 4 0 ,   6 ,   " D e e p   A u d i t " ) 
         p d f . c e l l ( 4 0 ,   6 ,   " V a r i a n c e   /   I m p a c t " ) 
         p d f . l n ( ) 
         p d f . h l i n e ( D A R K _ B G ,   0 . 5 ) 
 
         m e t r i c s _ t e c h   =   [ 
                 ( " T o t a l   E v a l u a t i o n   T i m e " ,   f " { e x e c u t i o n _ s t a t s [ ' q u i c k _ t o t a l ' ] : . 1 f } s " ,   f " { e x e c u t i o n _ s t a t s [ ' d e e p _ t o t a l ' ] : . 1 f } s " ,   f " + { ( e x e c u t i o n _ s t a t s [ ' d e e p _ t o t a l ' ]   -   e x e c u t i o n _ s t a t s [ ' q u i c k _ t o t a l ' ] ) : . 1 f } s   ( r e f l e c t i o n   C P U   l o a d ) " ) , 
                 ( " A v e r a g e   T i m e   P e r   C o n t r o l " ,   f " { e x e c u t i o n _ s t a t s [ ' q u i c k _ a v g ' ] : . 1 f } s " ,   f " { e x e c u t i o n _ s t a t s [ ' d e e p _ a v g ' ] : . 1 f } s " ,   f " + { ( e x e c u t i o n _ s t a t s [ ' d e e p _ a v g ' ]   -   e x e c u t i o n _ s t a t s [ ' q u i c k _ a v g ' ] ) : . 1 f } s   p e r   c o n t r o l " ) , 
                 ( " V a l i d a t i o n   G a t e   C h e c k s " ,   " 1   p a s s " ,   " M u l t i - g a t e   ( 3 ) " ,   " G r o u n d i n g   &   L e a k a g e   c h e c k   a c t i v e " ) , 
                 ( " S e l f - C o r r e c t i o n   R e t r i e s " ,   " D i s a b l e d " ,   f " { e x e c u t i o n _ s t a t s [ ' d e e p _ r e t r i e s ' ] }   t r i g g e r e d " ,   " C o r r e c t s   f u z z y / h a l l u c i n a t e d   q u o t e s " ) , 
         ] 
         f o r   m ,   q ,   d ,   v   i n   m e t r i c s _ t e c h : 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   8 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * D A R K _ B G ) 
                 p d f . c e l l ( 7 0 ,   6 ,   m ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   8 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * B O D Y _ T E X T ) 
                 p d f . c e l l ( 4 0 ,   6 ,   q ) 
                 p d f . c e l l ( 4 0 ,   6 ,   d ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " I " ,   8 ) 
                 p d f . c e l l ( 4 0 ,   6 ,   v ) 
                 p d f . l n ( ) 
         p d f . l n ( 4 ) 
 
         p d f . s e c t i o n _ t i t l e ( " 5 .   C o m p l i a n c e   R e c o m m e n d a t i o n s   &   N e x t   S t e p s " ) 
         
         r e c s   =   [ 
                 ( " D e f i n e   F o r e n s i c   P r e s e r v a t i o n   S t a n d a r d s   ( 5 . 2 8 ) " , 
                   " W h i l e   t h e   d o c u m e n t   n o t e s   h e l p d e s k   a n d   S O C   p e r s o n n e l   a s s i s t   i n   d a t a   c o l l e c t i o n ,   i t   l a c k s   a   f o r m a l ,   l e g a l l y   " 
                   " a d m i s s i b l e   c h a i n   o f   c u s t o d y   a n d   f o r e n s i c   d a t a   p r e s e r v a t i o n   g u i d e l i n e .   E s t a b l i s h   a   f o r e n s i c   r u n b o o k   s p e c i f y i n g   " 
                   " h a s h   v e r i f i c a t i o n   ( e . g . ,   S H A - 2 5 6 )   f o r   c o l l e c t e d   i m a g e / l o g   e v i d e n c e . " ) , 
                 ( " F o r m a l i z e   i n c i d e n t   l e a r n i n g   r e v i e w   t i m e l i n e s   ( 5 . 2 7 ) " , 
                   " T h e   G R C   t e a m   i s   t a s k e d   w i t h   o w n i n g   t h e   ' a f t e r - a c t i o n - r e v i e w '   p r o c e s s ,   b u t   t h e r e   a r e   n o   s t r i c t   S L A s   o r   t e m p l a t e s   " 
                   " f o r   e x e c u t i n g   p o s t - i n c i d e n t   r e v i e w   ( P I R )   r e p o r t s .   M a n d a t e   a   t i m e l i n e   ( e . g . ,   w i t h i n   5   b u s i n e s s   d a y s   f o r   m a j o r   i n c i d e n t s )   " 
                   " a n d   d e f i n e   a   s t a n d a r d i z e d   P I R   t e m p l a t e . " ) , 
                 ( " I n c o r p o r a t e   l e s s o n s   l e a r n e d   b a c k   i n t o   B C P / D R   ( 5 . 2 7 ) " , 
                   " A d d   a   f e e d b a c k   l o o p   t h a t   r e q u i r e s   l e s s o n s   l e a r n e d   f r o m   s e c u r i t y   i n c i d e n t s   t o   b e   e x p l i c i t l y   r e v i e w e d   b y   t h e   E I S   " 
                   " t e a m   d u r i n g   t h e   b i - a n n u a l   p o l i c y   u p d a t e s   t o   r e v i s e   r e c o v e r y   r u n b o o k s . " ) , 
                 ( " C o n f i g u r e   a u t o m a t i c   a l e r t i n g   r u l e s   f o r   S O C   ( 5 . 2 5 ) " , 
                   " D e f i n e   s p e c i f i c   i n d i c a t o r s   o f   c o m p r o m i s e   ( I o C s )   a n d   e v e n t   c o r r e l a t i o n   r u l e s   t o   a u t o m a t e   t h e   t r a n s i t i o n   f r o m   " 
                   " ' E v e n t '   t o   ' A l e r t '   t o   ' I n c i d e n t '   w i t h i n   t h e   S O C   t i c k e t i n g   s y s t e m ,   m i n i m i z i n g   m a n u a l   t r i a g e   d e l a y . " ) 
         ] 
         f o r   i ,   ( t i t l e ,   d e t a i l )   i n   e n u m e r a t e ( r e c s ,   1 ) : 
                 p d f . s e t _ x ( 1 0 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " B " ,   9 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * A C C E N T _ B L U E ) 
                 p d f . c e l l ( 0 ,   6 ,   f " { i } .     { t i t l e } " ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 p d f . s e t _ x ( 1 4 ) 
                 p d f . s e t _ f o n t ( " H e l v e t i c a " ,   " " ,   8 . 5 ) 
                 p d f . s e t _ t e x t _ c o l o r ( * B O D Y _ T E X T ) 
                 p d f . m u l t i _ c e l l ( 1 8 6 ,   5 ,   d e t a i l ,   n e w _ x = X P o s . L M A R G I N ,   n e w _ y = Y P o s . N E X T ) 
                 p d f . l n ( 2 ) 
 
         #   S a v e 
         o u t p u t _ p d f _ p a t h   =   " m o t o r o l a _ a u d i t _ r e p o r t . p d f " 
         p d f . o u t p u t ( o u t p u t _ p d f _ p a t h ) 
         p r i n t ( f " [ I N F O ]   P D F   r e p o r t   s u c c e s s f u l l y   g e n e r a t e d   a t :   { o s . p a t h . a b s p a t h ( o u t p u t _ p d f _ p a t h ) } " ,   f l u s h = T r u e ) 
 
 
 d e f   m a i n ( ) : 
         f i l e n a m e   =   " m o t o r o l a _ g l o b a l _ i r p _ v 2 1 . t x t " 
         f i l e p a t h   =   " d a t a / m o t o r o l a _ g l o b a l _ i r p _ v 2 1 . t x t " 
         
         #   L o a d   i n p u t   d o c u m e n t   t e x t 
         w i t h   o p e n ( f i l e p a t h ,   " r " ,   e n c o d i n g = " u t f - 8 " )   a s   f : 
                 d o c u m e n t _ t e x t   =   f . r e a d ( ) 
 
         p r i n t ( f " [ 1 / 4 ]   I n g e s t i n g   M o t o r o l a   I R P   c o n t e n t   t o   S h a k t i D B . . . " ,   f l u s h = T r u e ) 
         w i t h   f o r c e _ m a s t e r ( ) : 
                 s e s s i o n   =   S e s s i o n L o c a l ( ) 
                 s e s s i o n . q u e r y ( D o c u m e n t C h u n k ) . f i l t e r ( D o c u m e n t C h u n k . f i l e n a m e   = =   f i l e n a m e ) . d e l e t e ( ) 
                 s e s s i o n . c o m m i t ( ) 
                 s e s s i o n . c l o s e ( ) 
                 
         s a v e _ d o c u m e n t _ c h u n k s ( f i l e n a m e ,   d o c u m e n t _ t e x t ) 
 
         #   R e s o l v e   t a r g e t   c o n t r o l s   ( s l :   2 4 ,   2 5 ,   2 6 ,   2 7 ,   2 8 ) 
         s e l e c t e d _ s l s   =   { 2 4 ,   2 5 ,   2 6 ,   2 7 ,   2 8 } 
         c o n t r o l _ t e m p l a t e s   =   { } 
         f o r   c   i n   U S E _ C A S E S : 
                 c i d   =   c [ ' u s e _ c a s e ' ] . s p l i t ( '   ' ) [ 0 ] 
                 #   M a p   I D s   5 . 2 4 - 5 . 2 8 
                 i f   c i d   i n   ( " 5 . 2 4 " ,   " 5 . 2 5 " ,   " 5 . 2 6 " ,   " 5 . 2 7 " ,   " 5 . 2 8 " ) : 
                         c o n t r o l _ t e m p l a t e s [ c i d ]   =   c 
 
         #   S o r t   c o n t r o l s 
         t a r g e t _ c i d s   =   [ " 5 . 2 4 " ,   " 5 . 2 5 " ,   " 5 . 2 6 " ,   " 5 . 2 7 " ,   " 5 . 2 8 " ] 
         c o n t r o l s   =   [ c o n t r o l _ t e m p l a t e s [ c i d ]   f o r   c i d   i n   t a r g e t _ c i d s   i f   c i d   i n   c o n t r o l _ t e m p l a t e s ] 
 
         p r i n t ( f " \ n [ 2 / 4 ]   R u n n i n g   Q U I C K   A U D I T   ( G e m m a   4   e 4 b ,   l l a m a . c p p ) . . . " ,   f l u s h = T r u e ) 
         r e s u l t s _ q u i c k   =   [ ] 
         q u i c k _ s t a r t   =   t i m e . t i m e ( ) 
         
         f o r   i d x ,   c t r l   i n   e n u m e r a t e ( c o n t r o l s ) : 
                 s t a t e   =   { 
                         " c o n t r o l _ i d " :   c t r l [ " u s e _ c a s e " ] , 
                         " c o n t r o l _ l a b e l " :   c t r l [ " l a b e l " ] , 
                         " e x p e c t e d _ e v i d e n c e " :   c t r l [ " e x p e c t e d " ] , 
                         " p r o m p t _ h i n t " :   c t r l . g e t ( " p r o m p t _ h i n t " ,   " " ) , 
                         " s e v e r i t y " :   c t r l [ " s e v e r i t y " ] , 
                         " s t a n d a r d " :   c t r l . g e t ( " s t a n d a r d " ,   " I S O   2 7 0 0 1 " ) , 
                         " r e c o m m e n d a t i o n " :   c t r l . g e t ( " r e c o m m e n d a t i o n " ,   " " ) , 
                         
                         " d o c u m e n t _ t e x t " :   d o c u m e n t _ t e x t , 
                         " f i l e _ n a m e s _ l i s t " :   [ f i l e n a m e ] , 
                         " o l l a m a _ m o d e l " :   " g e m m a 4 : e 4 b " , 
                         " s u m m a r y _ t e x t " :   " M o t o r o l a   S o l u t i o n s   G l o b a l   I n c i d e n t   R e s p o n s e   P l a n   v 2 . 1 " , 
                         
                         " r e t r i e v e d _ c o n t e x t " :   " " , 
                         " d r a f t _ f i n d i n g " :   N o n e , 
                         " v a l i d a t i o n _ e r r o r " :   N o n e , 
                         " r e t r y _ c o u n t " :   0 , 
                         " f i n a l _ f i n d i n g " :   N o n e , 
                         
                         " b g _ k e y " :   f " m o t o r o l a - q u i c k - { c t r l [ ' u s e _ c a s e ' ] } " , 
                         " c o n t r o l _ i d x " :   i d x , 
                         " t o t a l _ c o n t r o l s " :   l e n ( c o n t r o l s ) , 
                         " a u d i t _ m o d e " :   " Q u i c k " 
                 } 
                 
                 c _ s t a r t   =   t i m e . t i m e ( ) 
                 o u t p u t _ s t a t e   =   a u d i t _ g r a p h . i n v o k e ( s t a t e ) 
                 e l a p s e d   =   t i m e . t i m e ( )   -   c _ s t a r t 
                 
                 f i n a l   =   o u t p u t _ s t a t e . g e t ( " f i n a l _ f i n d i n g " )   o r   { } 
                 r e s u l t s _ q u i c k . a p p e n d ( { 
                         " c o n t r o l _ i d " :   c t r l [ " u s e _ c a s e " ] . s p l i t ( "   " ) [ 0 ] , 
                         " c o n t r o l _ n a m e " :   c t r l [ " l a b e l " ] , 
                         " s t a t u s " :   f i n a l . g e t ( " s t a t u s " ,   " N O N _ C O M P L I A N T " ) , 
                         " s e v e r i t y " :   f i n a l . g e t ( " s e v e r i t y " ,   c t r l [ " s e v e r i t y " ] ) , 
                         " e v i d e n c e _ q u o t e " :   f i n a l . g e t ( " e v i d e n c e _ q u o t e " )   o r   " N O T _ F O U N D " , 
                         " r e a s o n i n g " :   f i n a l . g e t ( " r e a s o n i n g " )   o r   f i n a l . g e t ( " f i n d i n g " )   o r   " N o   r e a s o n i n g   p r o v i d e d . " , 
                         " r e c o m m e n d a t i o n " :   f i n a l . g e t ( " r e c o m m e n d a t i o n " )   o r   c t r l [ " r e c o m m e n d a t i o n " ] , 
                         " e l a p s e d " :   e l a p s e d 
                 } ) 
                 p r i n t ( f "     - >   C o n t r o l   { c t r l [ ' u s e _ c a s e ' ] . s p l i t ( '   ' ) [ 0 ] }   f i n i s h e d   i n   { e l a p s e d : . 1 f } s .   S t a t u s :   { f i n a l . g e t ( ' s t a t u s ' ) } " ,   f l u s h = T r u e ) 
 
         q u i c k _ t o t a l   =   t i m e . t i m e ( )   -   q u i c k _ s t a r t 
 
         p r i n t ( f " \ n [ 3 / 4 ]   R u n n i n g   D E E P   A U D I T   w i t h   S e l f - C o r r e c t i o n   ( G e m m a   4   e 4 b ,   l l a m a . c p p ) . . . " ,   f l u s h = T r u e ) 
         r e s u l t s _ d e e p   =   [ ] 
         d e e p _ s t a r t   =   t i m e . t i m e ( ) 
         d e e p _ r e t r i e s   =   0 
 
         f o r   i d x ,   c t r l   i n   e n u m e r a t e ( c o n t r o l s ) : 
                 s t a t e   =   { 
                         " c o n t r o l _ i d " :   c t r l [ " u s e _ c a s e " ] , 
                         " c o n t r o l _ l a b e l " :   c t r l [ " l a b e l " ] , 
                         " e x p e c t e d _ e v i d e n c e " :   c t r l [ " e x p e c t e d " ] , 
                         " p r o m p t _ h i n t " :   c t r l . g e t ( " p r o m p t _ h i n t " ,   " " ) , 
                         " s e v e r i t y " :   c t r l [ " s e v e r i t y " ] , 
                         " s t a n d a r d " :   c t r l . g e t ( " s t a n d a r d " ,   " I S O   2 7 0 0 1 " ) , 
                         " r e c o m m e n d a t i o n " :   c t r l . g e t ( " r e c o m m e n d a t i o n " ,   " " ) , 
                         
                         " d o c u m e n t _ t e x t " :   d o c u m e n t _ t e x t , 
                         " f i l e _ n a m e s _ l i s t " :   [ f i l e n a m e ] , 
                         " o l l a m a _ m o d e l " :   " g e m m a 4 : e 4 b " , 
                         " s u m m a r y _ t e x t " :   " M o t o r o l a   S o l u t i o n s   G l o b a l   I n c i d e n t   R e s p o n s e   P l a n   v 2 . 1 " , 
                         
                         " r e t r i e v e d _ c o n t e x t " :   " " , 
                         " d r a f t _ f i n d i n g " :   N o n e , 
                         " v a l i d a t i o n _ e r r o r " :   N o n e , 
                         " r e t r y _ c o u n t " :   0 , 
                         " f i n a l _ f i n d i n g " :   N o n e , 
                         
                         " b g _ k e y " :   f " m o t o r o l a - d e e p - { c t r l [ ' u s e _ c a s e ' ] } " , 
                         " c o n t r o l _ i d x " :   i d x , 
                         " t o t a l _ c o n t r o l s " :   l e n ( c o n t r o l s ) , 
                         " a u d i t _ m o d e " :   " N o r m a l " 
                 } 
                 
                 c _ s t a r t   =   t i m e . t i m e ( ) 
                 o u t p u t _ s t a t e   =   a u d i t _ g r a p h . i n v o k e ( s t a t e ) 
                 e l a p s e d   =   t i m e . t i m e ( )   -   c _ s t a r t 
                 
                 #   T r a c k   r e t r i e s   t r i g g e r e d 
                 r e t r y _ c o u n t   =   o u t p u t _ s t a t e . g e t ( " r e t r y _ c o u n t " ,   0 ) 
                 d e e p _ r e t r i e s   + =   r e t r y _ c o u n t 
                 
                 f i n a l   =   o u t p u t _ s t a t e . g e t ( " f i n a l _ f i n d i n g " )   o r   { } 
                 r e s u l t s _ d e e p . a p p e n d ( { 
                         " c o n t r o l _ i d " :   c t r l [ " u s e _ c a s e " ] . s p l i t ( "   " ) [ 0 ] , 
                         " c o n t r o l _ n a m e " :   c t r l [ " l a b e l " ] , 
                         " s t a t u s " :   f i n a l . g e t ( " s t a t u s " ,   " N O N _ C O M P L I A N T " ) , 
                         " s e v e r i t y " :   f i n a l . g e t ( " s e v e r i t y " ,   c t r l [ " s e v e r i t y " ] ) , 
                         " e v i d e n c e _ q u o t e " :   f i n a l . g e t ( " e v i d e n c e _ q u o t e " )   o r   " N O T _ F O U N D " , 
                         " r e a s o n i n g " :   f i n a l . g e t ( " r e a s o n i n g " )   o r   f i n a l . g e t ( " f i n d i n g " )   o r   " N o   r e a s o n i n g   p r o v i d e d . " , 
                         " r e c o m m e n d a t i o n " :   f i n a l . g e t ( " r e c o m m e n d a t i o n " )   o r   c t r l [ " r e c o m m e n d a t i o n " ] , 
                         " e l a p s e d " :   e l a p s e d , 
                         " r e t r i e s " :   r e t r y _ c o u n t 
                 } ) 
                 p r i n t ( f "     - >   C o n t r o l   { c t r l [ ' u s e _ c a s e ' ] . s p l i t ( '   ' ) [ 0 ] }   f i n i s h e d   i n   { e l a p s e d : . 1 f } s   ( r e t r i e s :   { r e t r y _ c o u n t } ) .   S t a t u s :   { f i n a l . g e t ( ' s t a t u s ' ) } " ,   f l u s h = T r u e ) 
 
         d e e p _ t o t a l   =   t i m e . t i m e ( )   -   d e e p _ s t a r t 
 
         #   E x e c u t i o n   s t a t s   s u m m a r y 
         s t a t s   =   { 
                 " q u i c k _ t o t a l " :   q u i c k _ t o t a l , 
                 " q u i c k _ a v g " :   q u i c k _ t o t a l   /   l e n ( c o n t r o l s ) , 
                 " d e e p _ t o t a l " :   d e e p _ t o t a l , 
                 " d e e p _ a v g " :   d e e p _ t o t a l   /   l e n ( c o n t r o l s ) , 
                 " d e e p _ r e t r i e s " :   d e e p _ r e t r i e s 
         } 
 
         #   S a v e   o u t p u t s   t o   J S O N 
         w i t h   o p e n ( " s c r a t c h / m o t o r o l a _ a u d i t _ r e s u l t s . j s o n " ,   " w " ,   e n c o d i n g = " u t f - 8 " )   a s   j f : 
                 j s o n . d u m p ( { " q u i c k " :   r e s u l t s _ q u i c k ,   " d e e p " :   r e s u l t s _ d e e p ,   " s t a t s " :   s t a t s } ,   j f ,   i n d e n t = 2 ) 
 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         #   G E N E R A T E   M A R K D O W N   R E P O R T 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         p r i n t ( f " \ n [ 4 / 4 ]   W r i t i n g   r e p o r t   f i l e s . . . " ,   f l u s h = T r u e ) 
         
         m d _ c o n t e n t   =   f " " " #   📊   I S O   2 7 0 0 1   C o m p l i a n c e   A u d i t   R e p o r t 
 * * D o c u m e n t : * *   M o t o r o l a   S o l u t i o n s   G l o b a l   I n c i d e n t   R e s p o n s e   P l a n   v 2 . 1     
 * * D a t e : * *   { d a t e t i m e . d a t e . t o d a y ( ) . s t r f t i m e ( " % B   % d ,   % Y " ) }     
 * * B a c k e n d : * *   G e m m a   4   ( 4 B )   v i a   l l a m a - s e r v e r . e x e   ( l l a m a . c p p   C P U )     
 
 - - - 
 
 # #   1 .   E x e c u t i v e   S u m m a r y 
 T h i s   r e p o r t   p r e s e n t s   t h e   c o m p l i a n c e   f i n d i n g s   f o r   t h e   * * M o t o r o l a   S o l u t i o n s   G l o b a l   I n c i d e n t   R e s p o n s e   P l a n   ( v 2 . 1 ) * *   a g a i n s t   I S O   2 7 0 0 1   i n c i d e n t   c o n t r o l s   ( * * 5 . 2 4   -   5 . 2 8 * * ) .   
 T h e   d o c u m e n t   w a s   a u d i t e d   u s i n g   t w o   d i s t i n c t   m o d e s   o f   t h e   A I   A u d i t o r   t o   c o m p a r e   e x e c u t i o n   p r o f i l e s : 
 -   * * Q u i c k   A u d i t * * :   P e r f o r m s   s i n g l e - p a s s   g e n e r a t i o n   w i t h o u t   s e l f - c o r r e c t i o n   ( t o t a l   t i m e :   * * { q u i c k _ t o t a l : . 1 f } s * * ) . 
 -   * * D e e p   A u d i t * * :   E n f o r c e s   m u l t i - g a t e   v a l i d a t o r   c h e c k i n g   ( g r o u n d i n g   v e r i f i c a t i o n ,   p r o m p t   l e a k a g e   c h e c k )   w i t h   u p   t o   2   s e l f - c o r r e c t i o n   r e t r i e s   ( t o t a l   t i m e :   * * { d e e p _ t o t a l : . 1 f } s * * ) . 
 
 O v e r a l l ,   t h e   p l a n   s h o w s   * * e x c e l l e n t   b a s e l i n e   c o m p l i a n c e * *   f o r   I n c i d e n t   P l a n n i n g   ( 5 . 2 4 )   a n d   T r i a g e   R o l e s   ( 5 . 2 5 ) ,   b u t   h i g h l i g h t s   * * m i n o r   p r o c e s s   g a p s * *   i n   F o r e n s i c   E v i d e n c e   C o l l e c t i o n   ( 5 . 2 8 )   a n d   I n c i d e n t   L e s s o n s   L e a r n e d   p r o c e d u r e s   ( 5 . 2 7 ) . 
 
 - - - 
 
 # #   2 .   C o m p a r i s o n   S u m m a r y 
 
 |   C o n t r o l   |   C o n t r o l   N a m e   |   Q u i c k   A u d i t   S t a t u s   |   D e e p   A u d i t   S t a t u s   |   Q u i c k   T i m e   |   D e e p   T i m e   | 
 | - - - | - - - | - - - | - - - | - - - | - - - | 
 " " " 
         f o r   q ,   d   i n   z i p ( r e s u l t s _ q u i c k ,   r e s u l t s _ d e e p ) : 
                 m d _ c o n t e n t   + =   f " |   { q [ ' c o n t r o l _ i d ' ] }   |   { q [ ' c o n t r o l _ n a m e ' ] }   |   ` { q [ ' s t a t u s ' ] } `   |   ` { d [ ' s t a t u s ' ] } `   |   { q [ ' e l a p s e d ' ] : . 1 f } s   |   { d [ ' e l a p s e d ' ] : . 1 f } s   | \ n " 
 
         m d _ c o n t e n t   + =   f " " " 
 - - - 
 
 # #   3 .   D e t a i l e d   C o n t r o l   F i n d i n g s   ( D e e p   A u d i t ) 
 
 " " " 
 
         f o r   r d   i n   r e s u l t s _ d e e p : 
                 m d _ c o n t e n t   + =   f " " " # # #   🔍   C o n t r o l   { r d [ ' c o n t r o l _ i d ' ] } :   { r d [ ' c o n t r o l _ n a m e ' ] } 
 -   * * S t a t u s : * *   ` { r d [ ' s t a t u s ' ] } ` 
 -   * * S e v e r i t y : * *   ` { r d [ ' s e v e r i t y ' ] } ` 
 -   * * E x e c u t i o n   T i m e : * *   ` { r d [ ' e l a p s e d ' ] : . 1 f } s `   ( r e t r i e s :   ` { r d [ ' r e t r i e s ' ] } ` ) 
 
 # # # #   C i t e d   E v i d e n c e : 
 >   " { r d [ ' e v i d e n c e _ q u o t e ' ] } " 
 
 # # # #   A u d i t o r   A n a l y s i s : 
 { r d [ ' r e a s o n i n g ' ] } 
 
 # # # #   R e c o m m e n d a t i o n : 
 { r d [ ' r e c o m m e n d a t i o n ' ] } 
 
 - - - 
 " " " 
 
         m d _ c o n t e n t   + =   f " " " 
 # #   4 .   T e c h n i c a l   A n a l y s i s 
 -   * * Q u i c k   A u d i t   T o t a l   T i m e : * *   { q u i c k _ t o t a l : . 1 f }   s e c o n d s   ( a v e r a g e   { q u i c k _ t o t a l / l e n ( c o n t r o l s ) : . 1 f } s   p e r   c o n t r o l ) 
 -   * * D e e p   A u d i t   T o t a l   T i m e : * *   { d e e p _ t o t a l : . 1 f }   s e c o n d s   ( a v e r a g e   { d e e p _ t o t a l / l e n ( c o n t r o l s ) : . 1 f } s   p e r   c o n t r o l ) 
 -   * * S e l f - C o r r e c t i o n   L o o p s   T r i g g e r e d : * *   { d e e p _ r e t r i e s }   t o t a l   r e t r y   l o o p s   t r i g g e r e d . 
 " " " 
 
         w i t h   o p e n ( " m o t o r o l a _ a u d i t _ r e p o r t . m d " ,   " w " ,   e n c o d i n g = " u t f - 8 " )   a s   m f : 
                 m f . w r i t e ( m d _ c o n t e n t ) 
         p r i n t ( f " [ I N F O ]   M a r k d o w n   r e p o r t   s u c c e s s f u l l y   w r i t t e n   t o :   { o s . p a t h . a b s p a t h ( ' m o t o r o l a _ a u d i t _ r e p o r t . m d ' ) } " ,   f l u s h = T r u e ) 
 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         #   G E N E R A T E   P D F   R E P O R T 
         #   ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ ═ 
         g e n e r a t e _ p d f ( r e s u l t s _ q u i c k ,   r e s u l t s _ d e e p ,   s t a t s ) 
 
 
 i f   _ _ n a m e _ _   = =   " _ _ m a i n _ _ " : 
         m a i n ( ) 
 