(defun fix-pattern-region (beg end)
  (interactive "r")
  (save-restriction
    (narrow-to-region beg end)
    (save-excursion
      (goto-char (point-min))
      (let ((i 0))
	(while (re-search-forward "^pattern [^=]+= StatsIx +\\([0-9]+\\)" nil t)
	  (delete-region (match-beginning 1) (match-end 0))
	  (goto-char (match-beginning 1))
	  (insert (format "%d" i))
	  (setq i (+ i 1)))))))
